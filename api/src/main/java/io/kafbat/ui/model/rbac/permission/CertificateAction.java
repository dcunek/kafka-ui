package io.kafbat.ui.model.rbac.permission;

import java.util.Set;
import org.apache.commons.lang3.EnumUtils;
import org.jetbrains.annotations.Nullable;

public enum CertificateAction implements PermissibleAction {

  VIEW,
  EDIT(VIEW)

  ;

  public static final Set<CertificateAction> ALTER_ACTIONS = Set.of(EDIT);

  private final PermissibleAction[] dependantActions;

  CertificateAction(CertificateAction... dependantActions) {
    this.dependantActions = dependantActions;
  }

  @Nullable
  public static CertificateAction fromString(String name) {
    return EnumUtils.getEnum(CertificateAction.class, name);
  }

  @Override
  public boolean isAlter() {
    return ALTER_ACTIONS.contains(this);
  }

  @Override
  public PermissibleAction[] dependantActions() {
    return dependantActions;
  }
}
