import ldap
from django.conf import settings

class LDAPManager:
    def __init__(self):
        self.ldap_server = settings.AUTH_LDAP_SERVER_URI
        self.bind_dn = settings.AUTH_LDAP_BIND_DN
        self.bind_password = settings.AUTH_LDAP_BIND_PASSWORD
        
    def authenticate_user(self, username, password):
        """Authenticate user against LDAP"""
        try:
            conn = ldap.initialize(self.ldap_server)
            conn.simple_bind_s(f"uid={username},{self.get_user_base()}", password)
            conn.unbind()
            return True
        except ldap.INVALID_CREDENTIALS:
            return False
        except Exception as e:
            print(f"LDAP Auth Error: {e}")
            return False
    
    def change_password(self, username, current_password, new_password):
        """Change user password in LDAP"""
        try:
            # First authenticate with current password
            if not self.authenticate_user(username, current_password):
                return False, "Current password is incorrect"
            
            conn = ldap.initialize(self.ldap_server)
            conn.simple_bind_s(self.bind_dn, self.bind_password)
            
            user_dn = f"uid={username},{self.get_user_base()}"
            
            # Modify password
            mod_list = [
                (ldap.MOD_REPLACE, 'userPassword', new_password.encode('utf-8'))
            ]
            
            conn.modify_s(user_dn, mod_list)
            conn.unbind()
            return True, "Password changed successfully"
            
        except ldap.INVALID_CREDENTIALS:
            return False, "Current password is incorrect"
        except ldap.CONSTRAINT_VIOLATION:
            return False, "Password does not meet complexity requirements"
        except Exception as e:
            print(f"LDAP Password Change Error: {e}")
            return False, f"Error changing password: {str(e)}"
    
    def get_user_base(self):
        """Extract base DN from bind DN"""
        # Extract base from bind DN (e.g., cn=admin,dc=example,dc=com -> dc=example,dc=com)
        parts = self.bind_dn.split(',')
        base_parts = [part for part in parts if part.startswith('dc=')]
        return ','.join(base_parts)
