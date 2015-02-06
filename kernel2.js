var zmq  = require('zmq')
var fs   = require('fs')
var util = require('util')
var vm   = require('vm')
var _    = require('lodash')

var config = JSON.parse(fs.readFileSync(process.argv[2]))

var sandbox = {
    module: module,
    require: require
}
var context = vm.createContext(sandbox)
var delim = '<IDS|MSG>';

var pubsock = zmq.createSocket('pub')
pubsock.bind(`tcp://${config.ip}:${config.iopub_port}`);

var heart = zmq.createSocket('rep')
heart.bind(`tcp://${config.ip}:${config.hb_port}`);

heart.on('message', function(data){
    console.log('|| thunk', arguments)
    heart.send(data)
})

var shellconn = zmq.createSocket('xrep');
shellconn.bind(`tcp://${config.ip}:${config.shell_port}`)

shellconn.on('message', function(){
    // console.log('~~', "HELLO DARNKENESS MY OLD FRIEND", _.toArray([1, 2, 3]))
    var args = _.toArray(arguments).map(x => x.toString()), idnet;
    
    while(args[0].toString() != delim) ident = args.shift();
    var signature = args[1],
        header = JSON.parse(args[2]),
        parent_header = JSON.parse(args[3]),
        metadata = JSON.parse(args[4]),
        content = JSON.parse(args[5]);

    // TODO: verify HMAC signature hmac(header, parent_header, metadata, content)
    

    if(header.msg_type == 'kernel_info_request'){
        send(shellconn, ident, header, 'kernel_info_reply', {
            protocol_version: [4, 0],
            language_version: process.version.replace(/[^\d\.]/g, '').split('.').map(x => parseInt(x, 10)),
            language: 'node'
        })
    }else if(header.msg_type == 'execute_request'){
        if(!content.silent) execution_counter++;
        // content.code
        // send_status('busy')
        send(pubsock, null, header, 'status', { execution_state: 'busy'})
        send(pubsock, null, header, 'pyin', { code: content.code })
        var result, reply;
        try{
            result = vm.runInContext(content.code, context, '<kernel>')
            reply = {
                status: 'ok',
                payload: [],
                user_variables: {},
                user_expressions: {},
                execution_count: execution_counter
            }
        } catch (e) {
            reply = {
                ename: e.name,
                evalue: e.message,
                etype: e.name,
                status: 'error',
                traceback: e.stack.split('\n'),
                execution_count: execution_counter
            }
            send(pubsock, null, header, 'pyerr', reply)
        }
        send(shellconn, ident, header, 'execute_reply', reply)
        if(!content.silent){
            send(pubsock, null, header, 'pyout', {
                data: {
                    'text/plain': util.inspect(result, {colors: true}) //util.inspect(result)
                }, 
                metadata: {}, 
                execution_count: execution_counter
            })
        }
        send(pubsock, null, header, 'status', { execution_state: 'idle'})
    }else if(header.msg_type == 'shutdown_request'){
        send(shellconn, ident, header, 'shutdown_reply', content)
    }else{
        console.log('!! unknown message type', header.msg_type)

        console.log('!! message', {
            ident: ident,
            signature: signature,
            header: header,
            parent_header: parent_header,
            metadata: metadata,
            content: content
        })
        
    }
})

shellconn.on('error', function(err){
    console.log('!!', 'error', err)
    console.error(err)
})

console.log('starting kernel')

// send(pubsock, null, null, 'status', { execution_state: 'starting'})

function send_status(exec_state){
    send(pubsock, null, header, 'status', { execution_state: exec_state})
}

var msg_counter = 1;
var execution_counter = 1;
function send(socket, ident, last_header, type, content){
    if(!last_header) last_header = {};

    var reply_header = {
        msg_id: msg_counter++,
        session: last_header.session,
        msg_type: type,
        username: last_header.username
    }
    var signature = '';
    var metadata = {};
    // console.log('!! sending', reply_header, content)
    var message = [
        delim,
        signature,
        JSON.stringify(reply_header),
        JSON.stringify(last_header),
        JSON.stringify(metadata),
        JSON.stringify(content)
    ]
    if(ident) message.unshift(ident);
    socket.send(message)
}