import frida


def attach_to_apsd() -> frida.core.Session:
    frida.kill("apsd")
    while True:
        try:
            return frida.attach("apsd")
        except frida.ProcessNotFoundError:
            pass


def redirect_courier(session: frida.core.Session):
    session.create_script(
        """
        var getaddrinfo_handle = Module.findExportByName(null, 'getaddrinfo');
        if (getaddrinfo_handle) {
            Interceptor.attach(getaddrinfo_handle, {
                onEnter: function(args) {
                    var node = Memory.readUtf8String(args[0]);
                    var service = Memory.readUtf8String(args[1]);
                    //this.res_ptr = args[3]
                    //console.log('[*] getaddrinfo("' + node + '", "' + service + '", ...)');
                    // Check for "courier.push.apple.com" in name
                    if (node.indexOf("courier.push.apple.com") !== -1) {
                        // Write "localhost" to the first argument
                        Memory.writeUtf8String(args[0], "localhost");
                        console.log('[*] getaddrinfo("' + node + '", ...) => getaddrinfo("localhost", ...)');
                    } else {
                        //console.log('[*] getaddrinfo("' + node + '", ...)');
                    }
                }
            });
            console.log('[+] getaddrinfo() hook installed.');
        }
        """
    ).load()


def trust_all_hosts(session: frida.core.Session):
    session.create_script(
        """
        // Hook -[APSTCPStream isTrust:validWithPolicy:forPeer:] to always return true
        var isTrust_handle = ObjC.classes.APSTCPStream['- isTrust:validWithPolicy:forPeer:'];
        if (isTrust_handle) {
            Interceptor.attach(isTrust_handle.implementation, {
                onEnter: function(args) {
                    console.log('[*] -[APSTCPStream isTrust:validWithPolicy:forPeer:]');
                    console.log('    - isTrust: ' + args[2]);
                    console.log('    - validWithPolicy: ' + args[3]);
                    console.log('    - forPeer: ' + args[4]);
                    //args[2] = true;
                    console.log('    => isTrust: ' + args[2]);
                },
                onLeave: function(retval) {
                    console.log('    <= ' + retval);
                    retval.replace(1);
                }
            });
            console.log('[+] -[APSTCPStream isTrust:validWithPolicy:forPeer:] hook installed.');
        }
        """
    ).load()
