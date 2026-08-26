import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:get/get.dart';
import 'package:path/path.dart';
import 'package:url_launcher/url_launcher_string.dart';
import 'package:window_manager/window_manager.dart';

class InstallPage extends StatefulWidget {
  const InstallPage({Key? key}) : super(key: key);

  @override
  State<InstallPage> createState() => _InstallPageState();
}

class _InstallPageState extends State<InstallPage> {
  final tabController = DesktopTabController(tabType: DesktopTabType.main);

  _InstallPageState() {
    Get.put<DesktopTabController>(tabController);
    const label = "install";
    tabController.add(TabInfo(
        key: label,
        label: label,
        closable: false,
        page: _InstallPageBody(
          key: const ValueKey(label),
        )));
  }

  @override
  void dispose() {
    super.dispose();
    Get.delete<DesktopTabController>();
  }

  @override
  Widget build(BuildContext context) {
    return DragToResizeArea(
      resizeEdgeSize: stateGlobal.resizeEdgeSize.value,
      enableResizeEdges: windowManagerEnableResizeEdges,
      child: Container(
        child: Scaffold(
            backgroundColor: Theme.of(context).colorScheme.background,
            body: DesktopTab(controller: tabController)),
      ),
    );
  }
}

class _InstallSetupData {
  const _InstallSetupData({
    required this.serverEnrollmentPassword,
    required this.friendlyName,
    required this.contactEmail,
    required this.password,
  });

  final String serverEnrollmentPassword;
  final String friendlyName;
  final String contactEmail;
  final String password;
}

class _InstallPageBody extends StatefulWidget {
  const _InstallPageBody({Key? key}) : super(key: key);

  @override
  State<_InstallPageBody> createState() => _InstallPageBodyState();
}

class _InstallPageBodyState extends State<_InstallPageBody>
    with WindowListener {
  late final TextEditingController controller;
  final RxBool startmenu = true.obs;
  final RxBool desktopicon = true.obs;
  final RxBool printer = false.obs;
  final RxBool showProgress = false.obs;
  final RxBool btnEnabled = true.obs;

  // todo move to theme.
  final buttonStyle = OutlinedButton.styleFrom(
    textStyle: TextStyle(fontSize: 14, fontWeight: FontWeight.normal),
    padding: EdgeInsets.symmetric(vertical: 15, horizontal: 12),
  );

  _InstallPageBodyState() {
    controller = TextEditingController(text: bind.installInstallPath());
    final installOptions = jsonDecode(bind.installInstallOptions());
    startmenu.value = installOptions['STARTMENUSHORTCUTS'] != '0';
    desktopicon.value = installOptions['DESKTOPSHORTCUTS'] != '0';
    printer.value = installOptions['PRINTER'] == '1';
  }

  @override
  void initState() {
    windowManager.addListener(this);
    super.initState();
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    controller.dispose();
    super.dispose();
  }

  @override
  void onWindowClose() {
    gFFI.close();
    super.onWindowClose();
    windowManager.setPreventClose(false);
    windowManager.close();
  }

  InkWell Option(RxBool option, {String label = ''}) {
    return InkWell(
      // todo mouseCursor: "SystemMouseCursors.forbidden" or no cursor on btnEnabled == false
      borderRadius: BorderRadius.circular(6),
      onTap: () => btnEnabled.value ? option.value = !option.value : null,
      child: Row(
        children: [
          Obx(
            () => Checkbox(
              visualDensity: VisualDensity(horizontal: -4, vertical: -4),
              value: option.value,
              onChanged: (v) =>
                  btnEnabled.value ? option.value = !option.value : null,
            ).marginOnly(right: 8),
          ),
          Expanded(
            child: Text(translate(label)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final double em = 13;
    final isDarkTheme = MyTheme.currentThemeMode() == ThemeMode.dark;
    return Scaffold(
        backgroundColor: null,
        body: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(translate('Installation'),
                  style: Theme.of(context).textTheme.headlineMedium),
              Row(
                children: [
                  Text('${translate('Installation Path')}:')
                      .marginOnly(right: 10),
                  Expanded(
                    child: TextField(
                      controller: controller,
                      readOnly: true,
                      decoration: InputDecoration(
                        contentPadding: EdgeInsets.all(0.75 * em),
                      ),
                    ).workaroundFreezeLinuxMint().marginOnly(right: 10),
                  ),
                  Obx(
                    () => OutlinedButton.icon(
                      icon: Icon(Icons.folder_outlined, size: 16),
                      onPressed: btnEnabled.value ? selectInstallPath : null,
                      style: buttonStyle,
                      label: Text(translate('Change Path')),
                    ),
                  )
                ],
              ).marginSymmetric(vertical: 2 * em),
              Option(startmenu, label: 'Create start menu shortcuts')
                  .marginOnly(bottom: 7),
              Option(desktopicon, label: 'Create desktop icon')
                  .marginOnly(bottom: 7),
              Option(printer, label: 'Install {$appName} Printer'),
              Container(
                  padding: EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: isDarkTheme
                        ? Color.fromARGB(135, 87, 87, 90)
                        : Colors.grey[100],
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.grey),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.info_outline_rounded, size: 32)
                          .marginOnly(right: 16),
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(translate('agreement_tip'))
                              .marginOnly(bottom: em),
                          InkWell(
                            hoverColor: Colors.transparent,
                            onTap: () => launchUrlString(
                                'https://rustdesk.com/privacy.html'),
                            child: Tooltip(
                              message: 'https://rustdesk.com/privacy.html',
                              child: Row(children: [
                                Icon(Icons.launch_outlined, size: 16)
                                    .marginOnly(right: 5),
                                Text(
                                  translate('End-user license agreement'),
                                  style: const TextStyle(
                                      decoration: TextDecoration.underline),
                                )
                              ]),
                            ),
                          ),
                        ],
                      )
                    ],
                  )).marginSymmetric(vertical: 2 * em),
              Row(
                children: [
                  Expanded(
                    // NOT use Offstage to wrap LinearProgressIndicator
                    child: Obx(() => showProgress.value
                        ? LinearProgressIndicator().marginOnly(right: 10)
                        : Offstage()),
                  ),
                  Obx(
                    () => OutlinedButton.icon(
                      icon: Icon(Icons.close_rounded, size: 16),
                      label: Text(translate('Cancel')),
                      onPressed:
                          btnEnabled.value ? () => windowManager.close() : null,
                      style: buttonStyle,
                    ).marginOnly(right: 10),
                  ),
                  Obx(
                    () => ElevatedButton.icon(
                      icon: Icon(Icons.done_rounded, size: 16),
                      label: Text(translate('Accept and Install')),
                      onPressed: btnEnabled.value ? install : null,
                      style: buttonStyle,
                    ),
                  ),
                  Offstage(
                    offstage: bind.installShowRunWithoutInstall(),
                    child: Obx(
                      () => OutlinedButton.icon(
                        icon: Icon(Icons.screen_share_outlined, size: 16),
                        label: Text(translate('Run without install')),
                        onPressed: btnEnabled.value
                            ? () => bind.installRunWithoutInstall()
                            : null,
                        style: buttonStyle,
                      ).marginOnly(left: 10),
                    ),
                  ),
                ],
              )
            ],
          ).paddingSymmetric(horizontal: 4 * em, vertical: 3 * em),
        ));
  }

  Future<_InstallSetupData?> _showInstallSetupDialog() async {
    final serverEnrollmentPasswordController = TextEditingController();
    final friendlyNameController = TextEditingController();
    final contactEmailController = TextEditingController();
    final passwordController = TextEditingController();
    final confirmPasswordController = TextEditingController();
    final emailRegex = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$');
    String? errorText;

    final result = await showDialog<_InstallSetupData>(
      context: this.context,
      barrierDismissible: false,
      builder: (dialogContext) {
        return StatefulBuilder(
          builder: (context, setDialogState) {
            void clearError() {
              if (errorText != null) {
                setDialogState(() => errorText = null);
              }
            }

            void submit() {
              final serverEnrollmentPassword =
                  serverEnrollmentPasswordController.text;
              final friendlyName = friendlyNameController.text.trim();
              final contactEmail = contactEmailController.text.trim();
              final password = passwordController.text;
              final confirmPassword = confirmPasswordController.text;

              String? validationError;

              if (serverEnrollmentPassword.isEmpty) {
                validationError = 'Server Enrollment Password is required.';
              } else if (!bind.installValidateAuthorizationPassword(
                password: serverEnrollmentPassword,
              )) {
                validationError =
                    'The Server Enrollment Password is incorrect.';
              } else if (friendlyName.isEmpty) {
                validationError = 'A friendly computer name is required.';
              } else if (contactEmail.isEmpty) {
                validationError = 'An email address is required.';
              } else if (!emailRegex.hasMatch(contactEmail)) {
                validationError = 'Enter a valid email address.';
              } else if (password.isEmpty != confirmPassword.isEmpty) {
                validationError =
                    'Enter the local access password in both fields, or leave both blank.';
              } else if (password.isNotEmpty && password.length < 8) {
                validationError =
                    'The local access password must be at least 8 characters.';
              } else if (password != confirmPassword) {
                validationError = 'The local access passwords do not match.';
              }

              if (validationError != null) {
                setDialogState(() => errorText = validationError);
                return;
              }

              Navigator.of(dialogContext).pop(
                _InstallSetupData(
                  serverEnrollmentPassword: serverEnrollmentPassword,
                  friendlyName: friendlyName,
                  contactEmail: contactEmail,
                  password: password,
                ),
              );
            }

            return AlertDialog(
              title: const Text('Computer setup'),
              content: SizedBox(
                width: 460,
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      TextField(
                        controller: serverEnrollmentPasswordController,
                        obscureText: true,
                        autofocus: true,
                        textInputAction: TextInputAction.next,
                        onChanged: (_) => clearError(),
                        decoration: const InputDecoration(
                          labelText: 'Server Enrollment Password',
                          helperText:
                              'Authorizes this installer and enrolls this computer with the managed server.',
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextField(
                        controller: friendlyNameController,
                        textInputAction: TextInputAction.next,
                        onChanged: (_) => clearError(),
                        decoration: const InputDecoration(
                          labelText: 'Friendly computer name',
                          hintText: 'Example: Office-PC-01',
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextField(
                        controller: contactEmailController,
                        textInputAction: TextInputAction.next,
                        onChanged: (_) => clearError(),
                        decoration: const InputDecoration(
                          labelText: 'Email address',
                          hintText: 'Example: you@company.com',
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextField(
                        controller: passwordController,
                        obscureText: true,
                        textInputAction: TextInputAction.next,
                        onChanged: (_) => clearError(),
                        decoration: const InputDecoration(
                          labelText: 'Local access password  optional',
                          helperText:
                              'Minimum 8 characters. A password requires 2FA setup.',
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextField(
                        controller: confirmPasswordController,
                        obscureText: true,
                        textInputAction: TextInputAction.done,
                        onChanged: (_) => clearError(),
                        onSubmitted: (_) => submit(),
                        decoration: const InputDecoration(
                          labelText: 'Confirm local access password',
                        ),
                      ),
                      const SizedBox(height: 12),
                      const Text(
                        'Leave both local password fields blank to require local approval for connections.',
                        style: TextStyle(fontSize: 12),
                      ),
                      if (errorText != null) ...[
                        const SizedBox(height: 12),
                        Text(
                          errorText!,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(),
                  child: const Text('Cancel'),
                ),
                ElevatedButton(
                  onPressed: submit,
                  child: const Text('Continue'),
                ),
              ],
            );
          },
        );
      },
    );

    serverEnrollmentPasswordController.dispose();
    friendlyNameController.dispose();
    contactEmailController.dispose();
    passwordController.dispose();
    confirmPasswordController.dispose();

    return result;
  }

  Future<void> install() async {
    final setup = await _showInstallSetupDialog();
    if (setup == null) {
      return;
    }

    // Close any already-installed/running instance first - besides being
    // needed for a clean file copy on reinstall, this also frees up the
    // local IPC channel that install-time 2FA verification (below) needs;
    // an old instance left running would otherwise still own it.
    await bind.installStopRunningInstance();

    if (setup.password.isNotEmpty) {
      // Set the friendly name locally now (installInstallMe below sets the
      // same value again once the actual install runs) so the 2FA QR code
      // generated next labels itself with it instead of the numeric ID.
      await bind.mainSetOption(
        key: 'preset-device-name',
        value: setup.friendlyName,
      );
      final enrolled = await enroll2faForInstall();
      if (!enrolled) {
        showToast(
          'Two-factor authentication was not verified. Installation did not start.',
        );
        return;
      }
    }

    if (!mounted) {
      return;
    }

    btnEnabled.value = false;
    showProgress.value = true;

    String args = '';
    if (startmenu.value) args += ' startmenu';
    if (desktopicon.value) args += ' desktopicon';
    if (printer.value) args += ' printer';

    await bind.installInstallMe(
      options: args,
      path: controller.text,
      friendlyName: setup.friendlyName,
      contactEmail: setup.contactEmail,
      password: setup.password,
      authorizationPassword: setup.serverEnrollmentPassword,
      enrollmentPassword: setup.serverEnrollmentPassword,
    );
  }

  void selectInstallPath() async {
    String? install_path = await FilePicker.platform
        .getDirectoryPath(initialDirectory: controller.text);
    if (install_path != null) {
      controller.text = join(install_path, await bind.mainGetAppName());
    }
  }
}
