import { certificatesApiClient as api } from 'lib/api';
import {
  QueryClient,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import { showSuccessAlert, showAlert } from 'lib/errorHandling';
import { CertificateCreation } from 'generated-sources';

export function useCertificates() {
  return useQuery(['certificates'], () => api.getCertificates(), {
    suspense: false,
  });
}

// Success handler for creating a certificate
const onCreateCertificateSuccess = (queryClient: QueryClient) => {
  showSuccessAlert({
    message: 'Certificate was created successfully',
  });
  queryClient.invalidateQueries(['clusters', 'certificates']);
};

export function useCreateCertificate() {
  const queryClient = useQueryClient();

  const mutate = useMutation(
    (certificateCreation: CertificateCreation) =>
      api.createCertificate({
        certificateCreation,
      }),
    {
      onSuccess() {
        onCreateCertificateSuccess(queryClient);
      },
    }
  );
  return {
    createResource: async (cert: CertificateCreation) => {
      return mutate.mutateAsync(cert);
    },
    ...mutate,
  };
}

// Hook to download a certificate
export function useDownloadCertificate() {
  const downloadCertificate = async (certificateUserName: string) => {
    try {
      const response = await api.downloadCertificateRaw({
        certificateUserName,
      });

      // Extract filename from Content-Disposition header
      const contentDisposition = response.raw.headers.get(
        'Content-Disposition'
      );
      const match = contentDisposition?.match(/filename="(.+?)"/);
      const fileName = match ? match[1] : certificateUserName; // Fallback to user-provided name

      // Download the file
      const blob = await response.value();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      showAlert('error', {
        id: '',
        title: 'Download Error',
        message: 'Failed to download Certificate',
      });
    }
  };

  return {
    downloadCertificate,
  };
}
