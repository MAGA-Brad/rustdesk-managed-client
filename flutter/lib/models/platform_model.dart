import 'native_model.dart' if (dart.library.html) 'web_model.dart';
import 'package:flutter_hbb/frb_generated.dart'
    if (dart.library.html) 'package:flutter_hbb/web/bridge.dart';

final platformFFI = PlatformFFI.instance;
final localeName = PlatformFFI.localeName;

RustLibApi get bind => platformFFI.ffiBind;

String ffiGetByName(String name, [String arg = '']) {
  return PlatformFFI.getByName(name, arg);
}

void ffiSetByName(String name, [String value = '']) {
  PlatformFFI.setByName(name, value);
}
