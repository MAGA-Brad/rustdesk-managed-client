import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/platform_model.dart';

class PrinterOptions {
  String action;
  List<String> printerNames;
  String printerName;

  PrinterOptions(
      {required this.action,
      required this.printerNames,
      required this.printerName});

  static PrinterOptions load() {
    var action = bind.crateFlutterFfiMainGetLocalOption(
        key: kKeyPrinterIncomingJobAction);
    if (![
      kValuePrinterIncomingJobDismiss,
      kValuePrinterIncomingJobDefault,
      kValuePrinterIncomingJobSelected
    ].contains(action)) {
      action = kValuePrinterIncomingJobDefault;
    }

    final printerNames = getPrinterNames();
    var selectedPrinterName =
        bind.crateFlutterFfiMainGetLocalOption(key: kKeyPrinterSelected);
    if (!printerNames.contains(selectedPrinterName)) {
      if (action == kValuePrinterIncomingJobSelected) {
        action = kValuePrinterIncomingJobDefault;
        bind.crateFlutterFfiMainSetLocalOption(
            key: kKeyPrinterIncomingJobAction,
            value: kValuePrinterIncomingJobDefault);
        if (printerNames.isEmpty) {
          selectedPrinterName = '';
        } else {
          selectedPrinterName = printerNames.first;
        }
        bind.crateFlutterFfiMainSetLocalOption(
            key: kKeyPrinterSelected, value: selectedPrinterName);
      }
    }

    return PrinterOptions(
        action: action,
        printerNames: printerNames,
        printerName: selectedPrinterName);
  }
}
