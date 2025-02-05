import { number, object, string } from 'yup';

const formSchema = object({
  certificateUserName: string()
    .required('Required field')
    .matches(
      /^[a-zA-Z0-9.]{3,}-(prod|dev)$/,
      'Certificate name must start with at least 3 alphanumeric characters or dots, followed by "prod" or "dev" at the end'
    ),
  password: string()
    .required('Required field')
    .min(8, 'Password name must be at least 8 characters'),
  expirationInDays: number()
    .positive('Positive only')
    .typeError('Numbers only')
    .required('Required field'),
  adminLdapGroup: string()
    .required('Required field')
    .matches(
      /admin-group$/,
      'Admin LDAP group should end with "admin-group" (not a technical requirement, just to have a nice config.yaml :-)'
    ),
});

export default formSchema;
