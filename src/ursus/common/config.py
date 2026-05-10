"""config.yml の読み込みとバリデーション"""
import socket
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class DatabaseConfig(BaseModel):
    path: str = "./data/edr.db"
    retention_days: int = 14


class ProcessSensorConfig(BaseModel):
    enabled: bool = True


class FileSensorConfig(BaseModel):
    enabled: bool = True
    watch_paths: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=lambda: ["*.swp", "*~"])
    # 同一 path への連続 modify を1ウィンドウに圧縮する秒数。0 で無効化。
    # 商用 EDR の "file write storm suppression" 相当。
    modify_debounce_sec: float = 2.0


class NetworkSensorConfig(BaseModel):
    enabled: bool = True
    poll_interval_sec: float = 2.0
    # 同一 (pid, remote_ip, remote_port) への ESTABLISHED 連発を1ウィンドウに
    # 抑制する秒数。LISTEN は常に通す。0 で無効化。
    established_debounce_sec: float = 5.0


class AuthSensorConfig(BaseModel):
    enabled: bool = True
    # journalctl の match フィルタ (同じフィールドの match は OR 結合)
    journal_units: list[str] = Field(default_factory=lambda: ["ssh.service", "sshd.service"])
    journal_comms: list[str] = Field(default_factory=lambda: ["sudo"])


class SensorConfig(BaseModel):
    hostname: str = "auto"
    process: ProcessSensorConfig = Field(default_factory=ProcessSensorConfig)
    file: FileSensorConfig = Field(default_factory=FileSensorConfig)
    network: NetworkSensorConfig = Field(default_factory=NetworkSensorConfig)
    auth: AuthSensorConfig = Field(default_factory=AuthSensorConfig)

    def resolved_hostname(self):
        if self.hostname == "auto":
            return socket.gethostname()
        return self.hostname


AllowedAction = Literal["alert", "kill_process", "quarantine_file", "block_network"]


class ResponseConfig(BaseModel):
    dry_run: bool = True
    allowed_actions: list[AllowedAction] = Field(default_factory=lambda: ["alert"])


class DetectorConfig(BaseModel):
    enabled: bool = True
    poll_interval_sec: float = 1.0
    rules_dir: str = "./rules"
    response: ResponseConfig = Field(default_factory=ResponseConfig)


class UIConfig(BaseModel):
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080
    events_per_page: int = 50

    @field_validator("bind_host")
    @classmethod
    def _enforce_loopback(cls, v):
        # 学習用途のため外部公開は禁止する。
        if v not in LOOPBACK_HOSTS:
            raise ValueError(f"ui.bind_host must be loopback; got {v!r}")
        return v


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"


class Config(BaseModel):
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    sensor: SensorConfig = Field(default_factory=SensorConfig)
    detector: DetectorConfig = Field(default_factory=DetectorConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def load_config(path):
    """YAML をロードして Config に変換する。"""
    with Path(path).open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Config.model_validate(data)
