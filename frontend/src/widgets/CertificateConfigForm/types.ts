export interface FormValues {
  certificateUserName: string;
  password: string;
  expirationInDays: number;
  adminLdapGroup: string;
  restrictedLdapGroup: string;
}

export const defaultValues: Partial<FormValues> = {
  certificateUserName: 'sys-dev',
  password: 'password',
  expirationInDays: 760,
  adminLdapGroup: 'sys-admin-group',
  restrictedLdapGroup: 'sys-user-group',
};
