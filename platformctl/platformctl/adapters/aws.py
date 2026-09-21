"""AWS Secrets Manager + ACM adapter. boto3 is imported lazily."""

from datetime import UTC, datetime
from typing import Any

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFoundError, SecretVersion


class AwsAdapter(CloudAdapter):
    def __init__(self, region: str | None = None) -> None:
        import boto3

        self._sm: Any = boto3.client("secretsmanager", region_name=region)
        self._acm: Any = boto3.client("acm", region_name=region)

    def get_secret(self, name: str) -> str:
        try:
            return str(self._sm.get_secret_value(SecretId=name)["SecretString"])
        except self._sm.exceptions.ResourceNotFoundException as exc:
            raise SecretNotFoundError(name) from exc

    def put_secret_version(self, name: str, value: str) -> SecretVersion:
        r = self._sm.put_secret_value(
            SecretId=name, SecretString=value, VersionStages=["AWSCURRENT"]
        )
        return SecretVersion(name=name, version=r["VersionId"], created=datetime.now(UTC))

    def list_secret_versions(self, name: str) -> list[SecretVersion]:
        r = self._sm.list_secret_version_ids(SecretId=name, IncludeDeprecated=True)
        versions = sorted(
            r.get("Versions", []), key=lambda v: v.get("CreatedDate", datetime.now(UTC))
        )
        return [
            SecretVersion(
                name=name,
                version=v["VersionId"],
                created=v.get("CreatedDate", datetime.now(UTC)),
                enabled="AWSCURRENT" in v.get("VersionStages", []),
                tags={"stages": ",".join(v.get("VersionStages", []))},
            )
            for v in versions
        ]

    def deprecate_version(self, name: str, version: str) -> None:
        # Removing all staging labels deprecates the version; AWS purges it after 24h.
        self._sm.update_secret_version_stage(
            SecretId=name, VersionStage="AWSPREVIOUS", RemoveFromVersionId=version
        )

    def list_certificates(self) -> list[Certificate]:
        out: list[Certificate] = []
        for c in self._acm.list_certificates().get("CertificateSummaryList", []):
            arn = c["CertificateArn"]
            detail = self._acm.describe_certificate(CertificateArn=arn)["Certificate"]
            out.append(
                Certificate(
                    name=arn.rsplit("/", 1)[-1],
                    subject=detail.get("Subject", ""),
                    not_after=detail.get("NotAfter", datetime.now(UTC)),
                    source="aws-acm",
                )
            )
        return out
