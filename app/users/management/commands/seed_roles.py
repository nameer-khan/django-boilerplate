# users/management/commands/seed_permissions.py
from django.core.management.base import BaseCommand
from users.models import Permission, Role, Permission_Role

class Command(BaseCommand):
    help = 'Seed permissions and assign them to roles'

    def handle(self, *args, **options):
        # Define permissions
        view_permission, _ = Permission.objects.get_or_create(scope='View')
        add_permission, _ = Permission.objects.get_or_create(scope='Add')
        edit_permission, _ = Permission.objects.get_or_create(scope='Edit')
        delete_permission, _ = Permission.objects.get_or_create(scope='Delete')

        # Get or create roles
        user_role, _ = Role.objects.get_or_create(name='User')
        admin_role, _ = Role.objects.get_or_create(name='Admin')

        # Assign permissions to roles
        Permission_Role.objects.get_or_create(role=user_role, permission=view_permission)
        Permission_Role.objects.get_or_create(role=user_role, permission=add_permission)
        Permission_Role.objects.get_or_create(role=user_role, permission=edit_permission)

        Permission_Role.objects.get_or_create(role=admin_role, permission=view_permission)
        Permission_Role.objects.get_or_create(role=admin_role, permission=add_permission)
        Permission_Role.objects.get_or_create(role=admin_role, permission=edit_permission)
        Permission_Role.objects.get_or_create(role=admin_role, permission=delete_permission)

        self.stdout.write(self.style.SUCCESS('Permissions and roles seeded successfully.'))
