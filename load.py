import argparse
import base64
import copy
import datetime as dt
import hmac
import json
import threading
import uuid
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Literal

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from email.utils import format_datetime
from urllib.parse import urljoin, urlparse


"""
Простой скрипт для нагрузочного тестирования:

1. Генерация клиента на основе JSON-шаблона (`client.json`).
2. Создание перевода на основе JSON-шаблона (`transfer.json` и др.).
3. Ожидание статуса операции `Accepted`.
4. Подписание операции с помощью PFX-сертификата.
5. Параллельный запуск нескольких потоков для нагрузки.

ВАЖНО: конечные URL эндпоинтов и точный формат подписи могут отличаться.
Отредактируйте константы `API_*` под ваш реальный API.
"""


# ========= НАСТРОЙКИ API (ОБЯЗАТЕЛЬНО ПРОВЕРИТЬ / ПРАВИТЬ ПОД КОНКРЕТНЫЙ СЕРВЕР) =========

# Все пути ниже указываются относительно BASE_URL.
# Пример BASE_URL: https://test.unistream.ru/opsapi_rgs/  или https://test.unistream.ru/

API_CREATE_CLIENT_PATH = "/v2/clients/"
API_CREATE_TRANSFER_PATH_TEMPLATE = "/v2/operations/transfer/{guid}"
API_GET_OPERATION_PATH_TEMPLATE = "/v2/operations/{operation_id}"
API_SIGN_OPERATION_PATH_TEMPLATE = "/v2/operations/{operation_id}/sign"


# ========= НАСТРОЙКИ HMAC-АВТОРИЗАЦИИ (ИЗ Postman-скрипта) =========
#
# ВАЖНО: эти значения зависят от окружения. Оставлены дефолты,
# но переопределяйте через CLI-аргументы (см. --app-id/--app-secret и др.).

DEFAULT_APP_ID = "4F5C53DE05C553AD756F"
DEFAULT_APP_SECRET = (
    "01p9Oo0zBQFNn70k8zm857GlIkA6UtaDuq6t1gKL+C0nRQt8l/tO7rlGkz0FnsO8vTwB1VGw9gB+ySNy"
)

DEFAULT_CASHIER = "3812"
DEFAULT_CASHIER_ID = "9f8c4ca322b24c1ab3b1ae24446ba9f0"
DEFAULT_CASHIER_LOGIN = "d.poshekhontsev"
DEFAULT_CASH_WINDOW = "1"
DEFAULT_POS_ID = "334579"


SecretEncoding = Literal["base64", "raw"]


@dataclass(frozen=True)
class AuthConfig:
    app_id: str
    app_secret: str
    secret_encoding: SecretEncoding
    cashier: str
    cashier_id: str
    cashier_login: str
    cash_window: str
    pos_id: str


@dataclass
class AuthHeaders:
    authorization: str
    date: str


def _b64decode_with_padding(value: str) -> bytes:
    """
    CryptoJS спокойно парсит base64 без паддинга, а стандартный Python — нет.
    Поэтому, если длина строки не кратна 4, добавляем '='.
    """
    s = value.strip()
    missing = (-len(s)) % 4
    if missing:
        s += "=" * missing
    return base64.b64decode(s)


def _build_signing_path(path: str) -> str:
    """
    Приводим path к формату, как в Postman-скрипте:
    - lower()
    - режем по '/'
    - убираем сегмент 'opsapi_rgs'
    - соединяем обратно
    """
    path = path.lower()
    has_trailing_slash = path.endswith("/")
    segments = [s for s in path.split("/") if s]  # убираем пустые, но trailing slash запомним отдельно
    filtered = [s for s in segments if s != "opsapi_rgs"]
    normalized = "/" + "/".join(filtered)
    if has_trailing_slash and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _get_secret_key_bytes(app_secret: str, encoding: SecretEncoding) -> bytes:
    if encoding == "raw":
        return app_secret.encode("utf-8")
    return _b64decode_with_padding(app_secret)


def build_hmac_headers(method: str, full_url: str, cfg: AuthConfig) -> AuthHeaders:
    """
    Формирование заголовков Authorization / Date по правилам из auth.js.
    """
    parsed = urlparse(full_url)
    signing_path = _build_signing_path(parsed.path)

    # Используем HTTP-дату в формате RFC 1123 (аналогично Date.toUTCString в JS, всегда EN)
    now_utc = dt.datetime.now(dt.timezone.utc)
    date_str = format_datetime(now_utc, usegmt=True)

    message = (
        f"{method.upper()}\n"
        f"\n"
        f"{date_str}\n"
        f"{signing_path}\n"
        f"{cfg.cashier}\n"
        f"{cfg.cashier_id}\n"
        f"{cfg.cashier_login}\n"
        f"{cfg.cash_window}\n"
        f"{cfg.pos_id}"
    )

    message_bytes = message.encode("utf-8")
    secret_key_bytes = _get_secret_key_bytes(cfg.app_secret, cfg.secret_encoding)
    digest = hmac.new(secret_key_bytes, message_bytes, sha256).digest()
    signature_b64 = base64.b64encode(digest).decode("ascii")

    auth_str = f"UNIHMAC {cfg.app_id}:{signature_b64}"
    return AuthHeaders(authorization=auth_str, date=date_str)


def build_common_headers(method: str, url: str, cfg: AuthConfig) -> Dict[str, str]:
    h = build_hmac_headers(method, url, cfg)
    return {
        "Authorization": h.authorization,
        "Date": h.date,
        "X-Unistream-Security-Cashier": cfg.cashier,
        "X-Unistream-Security-CashierId": cfg.cashier_id,
        "X-Unistream-Security-CashierLogin": cfg.cashier_login,
        "X-Unistream-Security-CashWindow": cfg.cash_window,
        "X-Unistream-Security-PosId": cfg.pos_id,
        "Content-Type": "application/json",
    }


# ========= РАБОТА С PFX И ПОДПИСЬЮ =========


def load_pfx(pfx_path: Path, password: str) -> Tuple[Any, Optional[x509.Certificate]]:
    data = pfx_path.read_bytes()
    key, cert, _ = pkcs12.load_key_and_certificates(
        data, password.encode("utf-8") if password else None
    )
    return key, cert


def sign_operation_with_pfx(
    private_key: Any, operation_id: str, extra_payload: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Пример локальной подписи операции.

    ПРЕДПОЛОЖЕНИЕ: подписываем строку с operation_id.
    Если спецификация другая – скорректируйте функцию.
    """
    to_sign = operation_id.encode("utf-8")
    signature = private_key.sign(
        to_sign,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature).decode("ascii")

    body = {"operationId": operation_id, "signature": signature_b64}
    if extra_payload:
        body.update(extra_payload)
    return body


# ========= ГЕНЕРАЦИЯ ДАННЫХ КЛИЕНТА / ПЕРЕВОДА =========


def load_json_template(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def generate_client_payload(template: Dict[str, Any]) -> Dict[str, Any]:
    payload = copy.deepcopy(template)
    new_id = str(uuid.uuid4())
    payload["id"] = new_id

    # простой генератор телефона: 79 + 9 случайных цифр
    random_suffix = str(uuid.uuid4().int)[0:9]
    phone = "79" + random_suffix
    payload["phoneNumber"] = phone

    # Документ – меняем серию/номер на псевдослучайные
    if payload.get("documents"):
        doc = payload["documents"][0]
        fields = doc.get("fields", {})
        fields["Series"] = str(uuid.uuid4().int)[0:4]
        fields["Number"] = str(uuid.uuid4().int)[0:6]
        doc["fields"] = fields
        payload["documents"][0] = doc

    return payload


def build_document_string_from_client(payload: Dict[str, Any]) -> Optional[str]:
    docs = payload.get("documents") or []
    if not docs:
        return None
    doc = docs[0]
    doc_type = doc.get("Type") or "Passport.RUS"
    fields = doc.get("fields", {})
    series = fields.get("Series", "")
    number = fields.get("Number", "")
    return f"{doc_type}.{series}{number}"


def generate_transfer_payload(
    template: Dict[str, Any], client_payload: Dict[str, Any]
) -> Dict[str, Any]:
    payload = copy.deepcopy(template)

    client_id = client_payload["id"]
    phone = client_payload.get("phoneNumber")
    doc_string = build_document_string_from_client(client_payload)

    client_ctx = payload.setdefault("clientContext", {})
    client_ctx["clientId"] = client_id
    if doc_string:
        client_ctx["documents"] = [doc_string]

    data = payload.setdefault("data", {})
    if phone:
        # В разных шаблонах поле называется Phone или phone
        if "Phone" in data:
            data["Phone"] = phone
        elif "phone" in data:
            data["phone"] = phone

    return payload


# ========= ВЗАИМОДЕЙСТВИЕ С API =========


def api_post_json(
    base_url: str, path: str, body: Dict[str, Any], cfg: AuthConfig
) -> Tuple[Dict[str, Any], requests.Response]:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    headers = build_common_headers("POST", url, cfg)
    resp = requests.post(url, headers=headers, json=body, timeout=30)
    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}
    if not resp.ok:
        raise RuntimeError(f"POST {url} failed: {resp.status_code} {data}")
    return data, resp


def api_get_json(
    base_url: str, path: str, cfg: AuthConfig
) -> Tuple[Dict[str, Any], requests.Response]:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    headers = build_common_headers("GET", url, cfg)
    resp = requests.get(url, headers=headers, timeout=30)
    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}
    if not resp.ok:
        raise RuntimeError(f"GET {url} failed: {resp.status_code} {data}")
    return data, resp


def wait_for_operation_terminal(
    base_url: str,
    operation_id: str,
    cfg: AuthConfig,
    poll_interval_sec: float = 1.0,
    timeout_sec: float = 60.0,
) -> Dict[str, Any]:
    import time

    end_time = time.time() + timeout_sec

    # Небольшая задержка перед первым опросом, чтобы сервер успел создать операцию
    time.sleep(poll_interval_sec)

    terminal_positive = {"Accepted"}
    terminal_negative = {"Corrupted", "Failed", "Rejected", "Canceled", "Cancelled"}

    while time.time() < end_time:
        path = API_GET_OPERATION_PATH_TEMPLATE.format(operation_id=operation_id)
        data, _ = api_get_json(base_url, path, cfg)
        status = (
            data.get("status")
            or data.get("Status")
            or data.get("operationStatus")
            or data.get("OperationStatus")
        )

        # Логируем текущий статус для наглядности
        print(f"[wait] operation {operation_id} status={status!r}")

        # Возвращаем при любом терминальном статусе
        if status in terminal_positive or status in terminal_negative:
            return data

        time.sleep(poll_interval_sec)

    raise TimeoutError(f"Operation {operation_id} did not reach terminal status in time")


def sign_operation(
    base_url: str,
    private_key: Any,
    operation_id: str,
    cfg: AuthConfig,
    extra_payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    body = sign_operation_with_pfx(private_key, operation_id, extra_payload)
    path = API_SIGN_OPERATION_PATH_TEMPLATE.format(operation_id=operation_id)
    resp_data, _ = api_post_json(base_url, path, body, cfg)
    return resp_data


# ========= СЦЕНАРИЙ ОДНОЙ ОПЕРАЦИИ =========


def run_scenario(
    base_url: str,
    client_template: Dict[str, Any],
    transfer_template: Dict[str, Any],
    private_key: Any,
    cfg: AuthConfig,
    thread_id: int,
) -> None:
    try:
        # 1. Создаём клиента
        client_payload = generate_client_payload(client_template)
        client_resp, _ = api_post_json(
            base_url, API_CREATE_CLIENT_PATH, client_payload, cfg
        )

        # На всякий случай, если сервер возвращает id по-другому
        client_id = (
            client_resp.get("id")
            or client_resp.get("clientId")
            or client_payload["id"]
        )

        print(f"[T{thread_id}] Client created: {client_id}")

        # 2. Создаём перевод
        transfer_payload = generate_transfer_payload(transfer_template, client_payload)

        # GUID для операции формируется на стороне клиента и передаётся в URL:
        # POST /v2/operations/transfer/{GUID}
        operation_id = str(uuid.uuid4())
        transfer_path = API_CREATE_TRANSFER_PATH_TEMPLATE.format(guid=operation_id)

        transfer_resp, _ = api_post_json(base_url, transfer_path, transfer_payload, cfg)
        print(f"[T{thread_id}] Transfer created, operationId={operation_id}, resp={transfer_resp}")

        # 3. Ждём терминальный статус (GET /v2/operations/{GUID})
        op_data = wait_for_operation_terminal(base_url, operation_id, cfg)
        status = (
            op_data.get("status")
            or op_data.get("Status")
            or op_data.get("operationStatus")
            or op_data.get("OperationStatus")
        )
        print(f"[T{thread_id}] Operation {operation_id} terminal status={status!r}, data={op_data}")

        if status != "Accepted":
            print(f"[T{thread_id}] Operation {operation_id} is not Accepted, skip signing")
            return

        # 4. Подписываем операцию только при Accepted
        sign_resp = sign_operation(base_url, private_key, operation_id, cfg)
        print(f"[T{thread_id}] Operation {operation_id} signed, response: {sign_resp}")

    except Exception as exc:
        print(f"[T{thread_id}] ERROR: {exc}")


# ========= MAIN / CLI =========


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Нагрузочный тест: создание клиента, перевод, подписание."
    )
    script_dir = Path(__file__).resolve().parent
    parser.add_argument(
        "--base-url",
        required=True,
        help="Базовый URL сервера, например https://test.unistream.ru/opsapi_rgs/",
    )
    parser.add_argument(
        "--client-template",
        type=Path,
        default=script_dir / "client.json",
        help="Путь к JSON-шаблону клиента (по умолчанию client.json рядом со скриптом).",
    )
    parser.add_argument(
        "--transfer-template",
        type=Path,
        default=script_dir / "transfer.json",
        help="Путь к JSON-шаблону перевода (по умолчанию transfer.json рядом со скриптом).",
    )
    parser.add_argument(
        "--pfx-path",
        type=Path,
        required=True,
        help="Путь к PFX-файлу сертификата.",
    )
    parser.add_argument(
        "--pfx-password",
        required=True,
        help="Пароль к PFX-файлу.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Количество параллельных потоков (одна операция на поток).",
    )
    parser.add_argument(
        "--app-id",
        default=DEFAULT_APP_ID,
        help="Application ID для UNIHMAC.",
    )
    parser.add_argument(
        "--app-secret",
        default=DEFAULT_APP_SECRET,
        help="Секрет для UNIHMAC (обычно base64-строка).",
    )
    parser.add_argument(
        "--secret-encoding",
        choices=("base64", "raw"),
        default="base64",
        help="Как интерпретировать --app-secret: base64 (по умолчанию) или raw.",
    )
    parser.add_argument("--cashier", default=DEFAULT_CASHIER)
    parser.add_argument("--cashier-id", default=DEFAULT_CASHIER_ID)
    parser.add_argument("--cashier-login", default=DEFAULT_CASHIER_LOGIN)
    parser.add_argument("--cash-window", default=DEFAULT_CASH_WINDOW)
    parser.add_argument("--pos-id", default=DEFAULT_POS_ID)
    args = parser.parse_args()

    client_template = load_json_template(args.client_template)
    transfer_template = load_json_template(args.transfer_template)

    private_key, cert = load_pfx(args.pfx_path, args.pfx_password)
    if cert:
        print(f"Loaded certificate: {cert.subject.rfc4514_string()}")

    threads = []
    cfg = AuthConfig(
        app_id=args.app_id,
        app_secret=args.app_secret,
        secret_encoding=args.secret_encoding,
        cashier=args.cashier,
        cashier_id=args.cashier_id,
        cashier_login=args.cashier_login,
        cash_window=args.cash_window,
        pos_id=args.pos_id,
    )
    for i in range(args.threads):
        t = threading.Thread(
            target=run_scenario,
            args=(
                args.base_url,
                client_template,
                transfer_template,
                private_key,
                cfg,
                i + 1,
            ),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
