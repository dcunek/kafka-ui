package io.kafbat.ui.controller;

import io.kafbat.ui.api.CertificatesApi;
import io.kafbat.ui.model.CertificateCreationDTO;
import io.kafbat.ui.model.CertificateDTO;
import io.kafbat.ui.service.CertificateStore;
import io.kafbat.ui.service.ConfigHelper;
import io.kafbat.ui.service.rbac.AccessControlService;
import io.kafbat.ui.util.ApplicationRestarter;
import io.kafbat.ui.util.DynamicConfigOperations;
import java.nio.file.Path;
import java.nio.file.Paths;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mapstruct.factory.Mappers;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@Slf4j
public class CertificatesController extends AbstractController implements CertificatesApi {
  private final DynamicConfigOperations dynamicConfigOperations;
  private final CertificateStore certificateStore;
  private final ConfigHelper configHelper;
  private final ApplicationRestarter restarter;
  private final AccessControlService accessControlService;

  private static final ApplicationConfigController.PropertiesMapper
      MAPPER = Mappers.getMapper(ApplicationConfigController.PropertiesMapper.class);

  @Override
  public Mono<ResponseEntity<Void>> createCertificate(Mono<CertificateCreationDTO> certificateCreationDto,
                                                      ServerWebExchange exchange) {


    return certificateCreationDto.flatMap(dto ->
            Mono.fromCallable(() -> certificateStore.storeCertificate(dto)) // store cert on disk
                .onErrorResume(ex -> {
                  log.error("Failed to store certificate", ex);
                  return Mono.error(new RuntimeException("Certificate storage failed", ex));
                })
                .zipWith(Mono.just(dto))
        )
        .doOnNext(tuple -> {
          var cert = tuple.getT1();
          var dto = tuple.getT2();

          // update app config
          var currentConfig = MAPPER.toDto(dynamicConfigOperations.getCurrentProperties());
          var newConfig = configHelper.updateConfig(currentConfig, dto, cert);
          dynamicConfigOperations.persist(MAPPER.fromDto(newConfig));

          // restart app
          restarter.requestRestart();
        })
        .thenReturn(ResponseEntity.ok().build());

  }

  @Override
  public Mono<ResponseEntity<Resource>> downloadCertificate(String certificateUserName, ServerWebExchange exchange) {
    // Validate the certificate name to prevent directory traversal attacks
    if (certificateUserName == null || certificateUserName.contains("..") || certificateUserName.contains("/")) {
      return Mono.just(ResponseEntity.badRequest().build());
    }

    // Construct the file path
    Path filePath = Paths.get(CertificateStore.certStorePath, certificateUserName + "-keystore.p12");
    FileSystemResource resource = new FileSystemResource(filePath);

    // Check if the file exists
    if (!resource.exists()) {
      return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    // Build response with headers
    return Mono.just(ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION,
            "attachment; filename=\"" + certificateUserName + "-keystore.p12" + "\"")
        .header(HttpHeaders.CONTENT_TYPE, "application/octet-stream")
        .body(resource));
  }

  @Override
  public Mono<ResponseEntity<Flux<CertificateDTO>>> getCertificates(ServerWebExchange exchange) {
    return AccessControlService.getUser()
        .flatMap(user -> {
          var userGroups = user.groups();
          var certificates = certificateStore.getAllCertificateMetadata();

          // If user is in "kafka-admin-group", return all records
          if (userGroups.stream().anyMatch(group -> group.contains(ConfigHelper.KAFKA_ADMIN_GROUP))) {
            return Mono.just(ResponseEntity.ok(Flux.fromIterable(certificates)));
          }

          // Filter certificates based on user’s admin LDAP groups
          var filteredCertificates = certificates.stream()
              .filter(cert -> userGroups.contains(cert.getAdminLdapGroup()))
              .toList();

          return Mono.just(ResponseEntity.ok(Flux.fromIterable(filteredCertificates)));
        });
  }
}
