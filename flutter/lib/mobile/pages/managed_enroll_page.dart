import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';

import '../../common.dart';
import '../../models/platform_model.dart';

/// Managed Android builds: the app only opens once RDS has approved this device. Until then it
/// shows the same enrollment form as the desktop installer (no local access password - nothing can
/// connect in to this device), then the pending / denied / blocked status from the directory worker.
class ManagedEnrollGate extends StatefulWidget {
  final Widget child;
  const ManagedEnrollGate({Key? key, required this.child}) : super(key: key);

  @override
  State<ManagedEnrollGate> createState() => _ManagedEnrollGateState();
}

class _ManagedEnrollGateState extends State<ManagedEnrollGate> {
  static final _emailRegex = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$');

  Timer? _timer;
  String _state = '';
  String _text = '';
  String _enrollError = '';
  String _myId = '';
  bool _submitting = false;
  String? _formError;

  final _password = TextEditingController();
  final _name = TextEditingController();
  final _email = TextEditingController();

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 2), (_) => _refresh());
    bind.crateFlutterFfiMainGetMyId().then((id) {
      if (mounted) setState(() => _myId = id);
    });
    bind.crateFlutterFfiMainGetOption(key: 'preset-device-name').then((v) {
      if (_name.text.isEmpty) _name.text = v;
    });
    bind.crateFlutterFfiMainGetOption(key: 'preset-device-email').then((v) {
      if (_email.text.isEmpty) _email.text = v;
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    _password.dispose();
    _name.dispose();
    _email.dispose();
    super.dispose();
  }

  void _refresh() {
    try {
      final status = jsonDecode(bind.crateFlutterFfiMainGetManagedDirectoryStatus());
      final state = (status['state'] ?? '').toString();
      final text = (status['text'] ?? '').toString();
      final enrollError = (status['enroll_error'] ?? '').toString();
      if (state != _state || text != _text || enrollError != _enrollError) {
        setState(() {
          _state = state;
          _text = text;
          _enrollError = enrollError;
          if (enrollError.isNotEmpty || state != 'not_enrolled') _submitting = false;
        });
      }
    } catch (_) {}
  }

  Future<void> _submit() async {
    final password = _password.text;
    final name = _name.text.trim();
    final email = _email.text.trim();
    String? error;
    if (password.isEmpty) {
      error = 'Server Enrollment Password is required.';
    } else if (!bind.crateFlutterFfiInstallValidateAuthorizationPassword(password: password)) {
      error = 'The Server Enrollment Password is incorrect.';
    } else if (name.isEmpty) {
      error = 'A friendly device name is required.';
    } else if (email.isEmpty) {
      error = 'An email address is required.';
    } else if (!_emailRegex.hasMatch(email)) {
      error = 'Enter a valid email address.';
    }
    setState(() {
      _formError = error;
      _submitting = error == null;
    });
    if (error != null) return;
    await bind.crateFlutterFfiInstallInstallMe(
      options: '',
      path: '',
      friendlyName: name,
      contactEmail: email,
      password: '',
      authorizationPassword: password,
      enrollmentPassword: password,
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_state == 'ready') return widget.child;
    return Scaffold(
      appBar: AppBar(centerTitle: true, title: const Text('RDC')),
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: ListView(
              padding: const EdgeInsets.all(24),
              shrinkWrap: true,
              children: _content(context),
            ),
          ),
        ),
      ),
    );
  }

  List<Widget> _content(BuildContext context) {
    final idLine = _myId.isEmpty ? <Widget>[] : [_muted('This device: $_myId')];
    switch (_state) {
      case 'not_enrolled':
        return _form(context);
      case 'enrolling':
        return [_heading('Enrolling…'), const SizedBox(height: 16), const LinearProgressIndicator(), ...idLine];
      case 'pending':
        return [
          _heading('Waiting for approval'),
          _body('An administrator needs to approve this device in RDS before it can connect to anything.'),
          if (_text.isNotEmpty) _muted(_text),
          ...idLine,
        ];
      case 'denied':
      case 'blocked':
      case 'revoked':
      case 'identity_changed':
        return [_heading('Not approved'), _body(_text), ...idLine];
      default:
        return [_heading('Connecting to RDS…'), if (_text.isNotEmpty) _muted(_text), ...idLine];
    }
  }

  List<Widget> _form(BuildContext context) {
    return [
      _heading('Enroll this device'),
      _body('Enter the Server Enrollment Password, a name for this device and your email address.'),
      const SizedBox(height: 16),
      TextField(
        controller: _password,
        obscureText: true,
        enabled: !_submitting,
        decoration: const InputDecoration(labelText: 'Server Enrollment Password'),
      ),
      TextField(
        controller: _name,
        enabled: !_submitting,
        decoration: const InputDecoration(labelText: 'Friendly device name', hintText: 'e.g. Front-Desk-Tablet'),
      ),
      TextField(
        controller: _email,
        enabled: !_submitting,
        keyboardType: TextInputType.emailAddress,
        decoration: const InputDecoration(labelText: 'Email address'),
      ),
      const SizedBox(height: 16),
      if (_formError != null || _enrollError.isNotEmpty)
        Text(_formError ?? _enrollError, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      const SizedBox(height: 8),
      ElevatedButton(
        onPressed: _submitting ? null : _submit,
        child: Text(_submitting ? 'Enrolling…' : 'Enroll'),
      ),
      if (_myId.isNotEmpty) _muted('This device: $_myId'),
    ];
  }

  Widget _heading(String text) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(text, style: Theme.of(context).textTheme.headlineSmall),
      );

  Widget _body(String text) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(text),
      );

  Widget _muted(String text) => Padding(
        padding: const EdgeInsets.only(top: 12),
        child: Text(text, style: TextStyle(color: MyTheme.darkGray)),
      );
}
