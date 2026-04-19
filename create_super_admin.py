from services.auth_service import create_super_admin

EMAIL = "k.handke@o2.pl"
PASSWORD = "handke300"
FULL_NAME = "Super Admin"

created_user_id = create_super_admin(
    email=EMAIL,
    password=PASSWORD,
    full_name=FULL_NAME,
    business_id=1
)

if created_user_id:
    print(f"Utworzono super admina. ID: {created_user_id}")
else:
    print("Użytkownik z tym e-mailem już istnieje.")