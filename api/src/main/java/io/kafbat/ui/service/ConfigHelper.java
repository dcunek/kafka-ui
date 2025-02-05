package io.kafbat.ui.service;

import io.kafbat.ui.model.ActionDTO;
import io.kafbat.ui.model.ApplicationConfigPropertiesDTO;
import io.kafbat.ui.model.ApplicationConfigPropertiesKafkaClustersInnerDTO;
import io.kafbat.ui.model.ApplicationConfigPropertiesKafkaClustersInnerSslDTO;
import io.kafbat.ui.model.ApplicationConfigPropertiesRbacRolesInnerDTO;
import io.kafbat.ui.model.ApplicationConfigPropertiesRbacRolesInnerPermissionsInnerDTO;
import io.kafbat.ui.model.ApplicationConfigPropertiesRbacRolesInnerSubjectsInnerDTO;
import io.kafbat.ui.model.CertificateCreationDTO;
import io.kafbat.ui.model.CertificateDTO;
import io.kafbat.ui.model.ResourceTypeDTO;
import java.util.HashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class ConfigHelper {

  private static final String TRUSTSTORE_LOCATION = "/etc/kafkaui/secrets/dna-server-truststore.jks";
  private static final String TRUSTSTORE_PASSWORD = "password";
  private static final String KAFKA_BOOTSTRAP = "broker1:9093";
  private static final String KAFKA_ADMIN_ROLE = "kafka-admin-role";
  public static final String KAFKA_ADMIN_GROUP = "kafka-admin-group";

  public ApplicationConfigPropertiesDTO updateConfig(ApplicationConfigPropertiesDTO currentConfig,
                                                      CertificateCreationDTO certificateCreation,
                                                      CertificateDTO certificate) {

    // Step 0: If config already contains cluster definition, update password and restart
    // This could happen the cert has been "renewed" using the same certificateUserName in "Create" form
    // Note: The form also enables to change the adminLdapGroup which could create new role, but I'm not doing it
    boolean updated = currentConfig.getKafka().getClusters().stream()
        .filter(cluster -> cluster.getName().equals(certificateCreation.getCertificateUserName()))
        .findFirst()
        .map(cluster -> {
          cluster.getProperties().replace("ssl.keystore.password", certificate.getPassword());
          cluster.getProperties().replace("ssl.keystore.location", certificate.getFileName());
          return true;
        })
        .orElse(false);

    if (updated) {
      return currentConfig;
    }

    // Step 1: Create new cluster definition
    var newCluster = createNewClusterDefinition(certificateCreation, certificate, currentConfig);

    // Step 2: Get or create USER role
    var roleName = certificateCreation.getAdminLdapGroup().replace("group", "role");
    var roles = currentConfig.getRbac().getRoles();
    var userAdminRole = roles.stream()
        .filter(role -> roleName.equals(role.getName()))
        .findFirst()
        .orElseGet(() -> {
          // Create if not exist
          var newRole = new ApplicationConfigPropertiesRbacRolesInnerDTO();
          newRole.setName(roleName);
          roles.add(newRole);

          // Create subject (reference to LDAP group)
          var subject = new ApplicationConfigPropertiesRbacRolesInnerSubjectsInnerDTO();
          subject.setProvider("LDAP");
          subject.setType("group");
          subject.setValue(certificateCreation.getAdminLdapGroup());
          newRole.getSubjects().add(subject);

          // Create permissions on new role
          createPermissions(newRole);

          return newRole;
        });

    // Step 3: add cluster name to userAdminRole
    if (!userAdminRole.getClusters().contains(newCluster.getName())) {
      userAdminRole.getClusters().add(newCluster.getName());
    }

    // Step 4: also add to kafkaAdminRole (if not done in previous step)
    if (!roleName.equals(KAFKA_ADMIN_ROLE)) {
      roles.stream()
          .filter(role -> KAFKA_ADMIN_ROLE.equals(role.getName())) // Match by name
          .findFirst()
          .ifPresent(kafkaAdminRole -> {
            if (!kafkaAdminRole.getClusters().contains(newCluster.getName())) {
              kafkaAdminRole.getClusters().add(newCluster.getName());
            }
          });
    }

    return currentConfig;
  }

  private void createPermissions(ApplicationConfigPropertiesRbacRolesInnerDTO role) {
    // Create CERTIFICATE permissions
    var p = new ApplicationConfigPropertiesRbacRolesInnerPermissionsInnerDTO();
    p.setResource(ResourceTypeDTO.CERTIFICATE);
    p.getActions().add(ActionDTO.VIEW);
    role.addPermissionsItem(p);

    // Create TOPIC permissions
    var p2 = new ApplicationConfigPropertiesRbacRolesInnerPermissionsInnerDTO();
    p2.setResource(ResourceTypeDTO.TOPIC);
    p2.value(".*");
    p2.getActions().add(ActionDTO.VIEW);
    p2.getActions().add(ActionDTO.MESSAGES_READ);
    p2.getActions().add(ActionDTO.MESSAGES_PRODUCE);
    role.addPermissionsItem(p2);

    // Create CONSUMER permissions
    var p3 = new ApplicationConfigPropertiesRbacRolesInnerPermissionsInnerDTO();
    p3.setResource(ResourceTypeDTO.CONSUMER);
    p3.value(".*");
    p3.getActions().add(ActionDTO.ALL);
    role.addPermissionsItem(p3);

    // Create ACL permissions
    var p4 = new ApplicationConfigPropertiesRbacRolesInnerPermissionsInnerDTO();
    p4.setResource(ResourceTypeDTO.ACL);
    p4.getActions().add(ActionDTO.VIEW);
    role.addPermissionsItem(p4);
  }

  private ApplicationConfigPropertiesKafkaClustersInnerDTO createNewClusterDefinition(
      CertificateCreationDTO certificateCreationDto,
      CertificateDTO certificate,
      ApplicationConfigPropertiesDTO currentConfig) {

    var newCluster = new ApplicationConfigPropertiesKafkaClustersInnerDTO();
    newCluster.setName(certificateCreationDto.getCertificateUserName());
    newCluster.setBootstrapServers(KAFKA_BOOTSTRAP); // TODO get bootstrap servers from certificateUserName suffix

    var sslTruststore = new ApplicationConfigPropertiesKafkaClustersInnerSslDTO();
    sslTruststore.setTruststoreLocation(TRUSTSTORE_LOCATION);
    sslTruststore.setTruststorePassword(TRUSTSTORE_PASSWORD);
    newCluster.setSsl(sslTruststore);

    var props = new HashMap<String, Object>();
    props.put("security.protocol", "SSL");
    props.put("ssl.keystore.password", certificateCreationDto.getPassword());
    props.put("ssl.keystore.location", certificate.getFileName());
    newCluster.setProperties(props);

    var clusters = currentConfig.getKafka().getClusters();
    clusters.add(newCluster);
    return newCluster;
  }

}
