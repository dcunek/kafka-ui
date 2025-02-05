import React from 'react';
import { Button } from 'components/common/Button/Button';
import { useForm, FormProvider } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import formSchema from 'widgets/CertificateConfigForm/schema';
import { FlexFieldset, StyledForm } from 'components/common/Form/Form.styled';
import Input from 'components/common/Input/Input';
import { useCreateCertificate } from 'lib/hooks/api/certificates';
import { FormValues, defaultValues } from 'widgets/CertificateConfigForm/types';
// import { toRequest } from 'widgets/CertificateConfigForm/lib';
import * as S from 'widgets/ClusterConfigForm/ClusterConfigForm.styled';
import PageHeading from 'components/common/PageHeading/PageHeading';
import { InfoParagraph } from 'components/Topics/Topic/Messages/Filters/Filters.styled';

const CertificateConfigForm: React.FC = () => {
  const methods = useForm<FormValues>({
    mode: 'all',
    resolver: yupResolver(formSchema),
    defaultValues: { ...defaultValues },
  });

  const create = useCreateCertificate();

  const onSubmit = async (data: FormValues) => {
    try {
      // const r = toRequest(data);
      await create.createResource(data);
    } catch (e) {
      // no custom error
    }
  };

  return (
    <>
      <PageHeading text="Create Certificate" />
      <FormProvider {...methods}>
        <StyledForm onSubmit={methods.handleSubmit(onSubmit)}>
          <FlexFieldset disabled={false}>
            <Input
              name="certificateUserName"
              id="certificateUserName"
              label="Certificate user name (CN in certificate, therefore Kafka user) *"
              withError
            />
            <Input
              name="password"
              id="password"
              label="Certificate password *"
              withError
            />
            <Input
              name="expirationInDays"
              id="expirationInDays"
              label="Expiration in days *"
              type="number"
              positiveOnly
              integerOnly
              withError
            />
            <hr />
            <InfoParagraph>
              This section is not directly related to the creation of the P12
              file. However, since Kafka UI does not provide built-in management
              for users, groups, or permissions (roles), we need to associate a
              **group** with a **role** in the configuration.
            </InfoParagraph>

            <InfoParagraph>
              A **role** determines which LDAP **group** can access specific
              **clusters** and what **permissions** (user operations in this UI)
              are granted. The role will be defined in the configuration YAML
              file with the following permissions:
              <ul>
                <li>CERTIFICATE: VIEW</li>
                <li>TOPIC: VIEW, MESSAGES_READ, MESSAGES_PRODUCE</li>
                <li>CONSUMER: VIEW, DELETE, RESET_OFFSETS</li>
              </ul>
            </InfoParagraph>

            <InfoParagraph>
              The **group** must exist in LDAP, along with its users, to allow
              access to the Kafka UI. This group should be considered an admin
              group because users assigned to it will have the ability to view
              view certificate passwords and download certificates. For more
              details, refer to the{' '}
              <a href="https://ui.docs.kafbat.io/configuration/rbac-role-based-access-control">
                Kafka UI RBAC documentation
              </a>
              .
            </InfoParagraph>
            <Input
              name="adminLdapGroup"
              id="adminLdapGroup"
              label="LDAP group allowing privileged users to view and download certicates *"
              withError
            />
            <hr />
            <S.ButtonWrapper>
              <Button
                type="submit"
                buttonSize="L"
                buttonType="primary"
                disabled={false}
                inProgress={false}
              >
                Create client certificate
              </Button>
            </S.ButtonWrapper>
          </FlexFieldset>
        </StyledForm>
      </FormProvider>
    </>
  );
};

export default CertificateConfigForm;
