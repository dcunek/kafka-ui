import React, { useMemo } from 'react';
import PageHeading from 'components/common/PageHeading/PageHeading';
import Table from 'components/common/NewTable';
import { Button } from 'components/common/Button/Button';
import { ActionCanButton } from 'components/common/ActionComponent';
import { ColumnDef } from '@tanstack/react-table';
import {
  useCertificates,
  useDownloadCertificate,
} from 'lib/hooks/api/certificates';
import { useGetUserInfo } from 'lib/hooks/api/roles';
import { Action, Certificate, ResourceType } from 'generated-sources';
import { certificateCreatePath } from 'lib/paths';

import * as S from './index.styled';

// Define the DownloadButton component
const DownloadButton: React.FC<{ fileName: string }> = ({ fileName }) => {
  const { downloadCertificate } = useDownloadCertificate(); // Hook at the top level

  const handleDownload = () => {
    downloadCertificate(fileName); // Call the download function
  };

  return (
    <Button buttonSize="S" buttonType="secondary" onClick={handleDownload}>
      Download
    </Button>
  );
};

const CertificateList: React.FC = () => {
  const certificates = useCertificates();
  const certificateList = certificates.data || [];
  const { data } = useGetUserInfo();

  // Check permissions
  const hasPermissions = useMemo(() => {
    if (!data?.rbacEnabled) return true;
    return !!data?.userInfo?.permissions.some(
      (permission) =>
        permission.resource === ResourceType.CERTIFICATE &&
        permission.actions.includes(Action.EDIT)
    );
  }, [data]);

  // Columns for Certificates Table
  const columns = useMemo<ColumnDef<Certificate>[]>(
    () => [
      { header: 'Certificate User Name', accessorKey: 'certificateUserName' },
      { header: 'Password', accessorKey: 'password' },
      { header: 'Creation Date', accessorKey: 'creation' },
      { header: 'Expiration Date', accessorKey: 'expiration' },
      { header: 'Admin group', accessorKey: 'adminLdapGroup' },
      { header: 'File Name', accessorKey: 'fileName' },
      {
        header: 'Actions',
        // eslint-disable-next-line react/no-unstable-nested-components
        cell: ({ row }) => (
          <DownloadButton fileName={row.original.certificateUserName ?? ''} />
        ),
      },
    ],
    []
  );

  return (
    <>
      <PageHeading text="Certificates" />
      <S.Toolbar>
        <ActionCanButton
          buttonType="primary"
          buttonSize="M"
          canDoAction={hasPermissions}
          to={certificateCreatePath}
        >
          Create new Certificate
        </ActionCanButton>
      </S.Toolbar>
      <Table
        columns={columns}
        data={certificateList}
        enableSorting
        emptyMessage="No certificates available."
      />
    </>
  );
};

export default CertificateList;
