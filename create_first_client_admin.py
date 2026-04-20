from services.auth_service import create_client_admin

EMAIL = "admin@handkeholding.com"
PASSWORD = "kurwamac"
FULL_NAME = "Administrator"
BUSINESS_ID = 1

def create_first_admin():
    user_id = create_client_admin(
        business_id=BUSINESS_ID,
        email=EMAIL,
        password=PASSWORD,
        full_name=FULL_NAME
    )

    if user_id:
        print("Konto klienta zostało utworzone. ID:", user_id)
    else:
        print("Nie udało się utworzyć konta.")

if __name__ == "__main__":
    create_first_admin()