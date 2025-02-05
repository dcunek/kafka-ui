import { CertificateCreation } from 'generated-sources';

import { FormValues } from './types';

export function toRequest(formValue: FormValues): CertificateCreation {
  return {
    certificateUserName: formValue.certificateUserName || '',
    password: formValue.password,
    expirationInDays: formValue.expirationInDays,
    adminLdapGroup: formValue.adminLdapGroup,
    restrictedLdapGroup: formValue.restrictedLdapGroup,
  };
}
