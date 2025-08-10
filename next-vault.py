import json
import os
import getpass
import requests
from cryptography.fernet import Fernet
from hashlib import sha256

DATA_FILE = "vault_data.json"

def derive_key(password: str) -> bytes:
    """Генерация ключа из пароля."""
    digest = sha256(password.encode()).digest()
    return Fernet.generate_key()[:16] + digest[:16]  # смешиваем для устойчивости

def get_fernet(password: str) -> Fernet:
    return Fernet(sha256(password.encode()).digest()[:32])

def load_vault(password: str):
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "rb") as f:
        encrypted = f.read()
    if not encrypted:
        return {}
    fernet = get_fernet(password)
    try:
        decrypted = fernet.decrypt(encrypted).decode()
        return json.loads(decrypted)
    except:
        print("❌ Неверный пароль или повреждённый файл.")
        exit(1)

def save_vault(vault: dict, password: str):
    fernet = get_fernet(password)
    encrypted = fernet.encrypt(json.dumps(vault).encode())
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)

def check_balance(address: str) -> dict:
    """Проверка баланса через blockchain API (BTC в примере)."""
    url = f"https://blockchain.info/rawaddr/{address}"
    resp = requests.get(url)
    if resp.status_code != 200:
        return {"error": "Не удалось получить данные"}
    data = resp.json()
    return {
        "final_balance": data.get("final_balance", 0) / 1e8,
        "n_tx": data.get("n_tx", 0)
    }

def main():
    print("🔐 Next-Vault — умный сейф для криптоадресов")
    password = getpass.getpass("Введите мастер-пароль: ")

    vault = load_vault(password)

    while True:
        print("\n1. Добавить адрес")
        print("2. Показать адреса")
        print("3. Проверить баланс")
        print("4. Выход")
        choice = input("Выберите действие: ").strip()

        if choice == "1":
            addr = input("Введите криптоадрес: ").strip()
            note = input("Заметка: ").strip()
            vault[addr] = {"note": note}
            save_vault(vault, password)
            print("✅ Адрес сохранён.")
        elif choice == "2":
            if not vault:
                print("📭 Список пуст.")
            else:
                for a, meta in vault.items():
                    print(f"{a} — {meta['note']}")
        elif choice == "3":
            for addr in vault:
                info = check_balance(addr)
                if "error" in info:
                    print(f"{addr} — ошибка запроса")
                else:
                    print(f"{addr}: {info['final_balance']} BTC, транзакций: {info['n_tx']}")
        elif choice == "4":
            print("👋 Выход.")
            break
        else:
            print("❌ Неверный выбор.")

if __name__ == "__main__":
    main()
