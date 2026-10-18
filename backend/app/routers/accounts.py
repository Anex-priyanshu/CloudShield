"""Accounts router."""
import json
import asyncio
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db import get_db
from app.models import CloudAccount, AccountProvider, AccountStatus, User, UserRole
from app.schemas import AccountCreate, AccountOut, TestConnectionResponse
from app.auth import get_current_user, get_current_admin, encrypt_credentials, decrypt_credentials

router = APIRouter(prefix="/accounts", tags=["accounts"])

READ_ONLY_POLICY = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "s3:GetBucketTagging",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents",
        "rds:DescribeDBInstances",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
"""


@router.get("", response_model=List[AccountOut])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(CloudAccount).order_by(CloudAccount.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=AccountOut)
async def create_account(
    body: AccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    creds = {}
    if body.access_key_id and body.secret_access_key:
        creds = {"access_key_id": body.access_key_id, "secret_access_key": body.secret_access_key}
    elif body.assume_role_arn:
        creds = {"assume_role_arn": body.assume_role_arn}

    account = CloudAccount(
        name=body.name,
        provider=body.provider,
        region=body.region,
        auth_type="access_key" if creds.get("access_key_id") else "assume_role",
        credentials_encrypted=encrypt_credentials(creds) if creds else None,
        is_demo=body.is_demo,
        status=AccountStatus.demo if body.is_demo else AccountStatus.connected,
    )
    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account


@router.post("/demo", response_model=AccountOut)
async def create_demo_account(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    account = CloudAccount(
        name="Demo-Sandbox (simulated)",
        provider=AccountProvider.demo,
        region="us-east-1",
        account_id="123456789012",
        auth_type="demo",
        credentials_encrypted=None,
        is_demo=True,
        status=AccountStatus.demo,
    )
    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account


@router.post("/{account_id}/test", response_model=TestConnectionResponse)
async def test_connection(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(CloudAccount).where(CloudAccount.id == account_id))
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    if account.is_demo:
        return TestConnectionResponse(success=True, account_id="123456789012", message="Demo account – always connected")

    if not account.credentials_encrypted:
        raise HTTPException(status_code=400, detail="No credentials stored")

    creds = decrypt_credentials(account.credentials_encrypted)

    try:
        from app.collectors.aws_collector import test_connection as aws_test
        conn_result = await asyncio.get_event_loop().run_in_executor(
            None, aws_test, creds, account.region
        )
        if conn_result["success"]:
            account.account_id = conn_result["account_id"]
            account.status = AccountStatus.connected
            await db.commit()
        else:
            account.status = AccountStatus.error
            await db.commit()
        return TestConnectionResponse(**conn_result)
    except Exception as e:
        return TestConnectionResponse(success=False, message=str(e))


@router.delete("/{account_id}", status_code=204)
async def delete_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(CloudAccount).where(CloudAccount.id == account_id))
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    await db.delete(account)
    await db.commit()


@router.get("/policy", response_model=dict)
async def get_required_policy(current_user: User = Depends(get_current_user)):
    return {"policy": READ_ONLY_POLICY}
