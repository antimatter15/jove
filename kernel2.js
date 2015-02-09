// figure out how to properly handle sigints without killing state      

var zmq  = require('zmq')
var fs   = require('fs')
var util = require('util')
var vm   = require('vm')
var _    = require('lodash')
var to5  = require("6to5")
var path = require('path')

var config = JSON.parse(fs.readFileSync(process.argv[2]))

module.filename = path.join(process.cwd(), '<kernel>')
module.paths = require('module')._nodeModulePaths(process.cwd())

function pyout(mime, text){
    var data = {};
    data[mime] = text;
    send(pubsock, null, 'pyout', {
        data: data, 
        metadata: {}, 
        execution_count: execution_counter
    })
}

var sandbox = {
    module: module,
    require: require,
    console: {
        log: function(str){ pyout('text/plain', str) },
        error: function(str){
            send(pubsock, null, 'pyerr', {
                data: {
                    'text/plain': str
                }, 
                metadata: {}, 
                execution_count: execution_counter
            })
        },
        image: function(buf){
            pyout('image/png', buf.toString('base64'))
        },
        html: function(str){
            pyout('text/html', str)
        }
    }
}
var context = vm.createContext(sandbox)
var delim = '<IDS|MSG>';

var pubsock = zmq.createSocket('pub')
pubsock.bind(`tcp://${config.ip}:${config.iopub_port}`);
pubsock.on('message', function(){
    console.log('|| pubsock', arguments)
})


var heart = zmq.createSocket('rep')
heart.bind(`tcp://${config.ip}:${config.hb_port}`);
heart.on('message', function(data){
    console.log('|| thunk', arguments)
    heart.send(data)
})

var last_header = {};

var shellconn = zmq.createSocket('xrep');
shellconn.bind(`tcp://${config.ip}:${config.shell_port}`)
shellconn.on('message', function(){
    var args = _.toArray(arguments).map(x => x.toString()), idnet;
    
    while(args[0].toString() != delim) ident = args.shift();
    var signature = args[1],
        header = JSON.parse(args[2]),
        parent_header = JSON.parse(args[3]),
        metadata = JSON.parse(args[4]),
        content = JSON.parse(args[5]);

    // TODO: verify HMAC signature hmac(parent_metadata, content)
    last_header = header;

    console.log('!! message', {
        ident: ident,
        signature: signature,
        header: header,
        parent_header: parent_header,
        metadata: metadata,
        content: content
    })

    if(header.msg_type == 'kernel_info_request'){
        send(shellconn, ident, 'kernel_info_reply', {
            protocol_version: [4, 0],
            language_version: process.version.replace(/[^\d\.]/g, '').split('.').map(x => parseInt(x, 10)),
            language: 'node'
        })
    }else if(header.msg_type == 'execute_request'){
        if(!content.silent) execution_counter++;
        // content.code
        // send_status('busy')
        send(pubsock, null, 'status', { execution_state: 'busy'})
        send(pubsock, null, 'pyin', { code: content.code })
        var result, reply;
        try{
            var code = to5.transform(content.code, {
                blacklist: ['regenerator'],
                whitelist: ['asyncToGenerator', 'es6.blockScoping']
            }).code;
            // pyout('text/plain', code)
            result = vm.runInContext(code, context, '<kernel>')
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
            send(pubsock, null, 'pyerr', reply)
        }
        send(shellconn, ident, 'execute_reply', reply)
        if(!content.silent && result !== undefined){
            send(pubsock, null, 'pyout', {
                data: {
                    'text/plain': util.inspect(result, {colors: true}) //util.inspect(result)
                }, 
                metadata: {}, 
                execution_count: execution_counter
            })
        }
        send(pubsock, null, 'status', { execution_state: 'idle'})
    }else if(header.msg_type == 'shutdown_request'){
        send(shellconn, ident, 'shutdown_reply', content)
    }else{
        console.log('!! unknown message type', header.msg_type)

        
    }
})

shellconn.on('error', function(err){
    console.log('!!', 'error', err)
    console.error(err)
})

process.on('SIGINT', function() {
  console.log('Got SIGINT? Nope, Chuck Snowclone!');
})

// process.stderr.write = (function(write){
//     // return write('wumbo' + write)
//     // write.apply(process.stderr, [args);
//     return function(str){
//         return write.apply(process.stderr, arguments);
//     }
// })(process.stderr.write);

// process.stdout.write = (function(write){
//     return function(str){
//         send(pubsock, null, null, 'pyout', {
//             data: {
//                 'text/plain': str
//             }, 
//             metadata: {}, 
//             execution_count: execution_counter
//         })
//         return write.apply(process.stdout, arguments);
//     }
// })(process.stdout.write);

console.log('starting kernel')

// send(pubsock, null, 'status', { execution_state: 'starting'})

function send_status(exec_state){
    send(pubsock, null, 'status', { execution_state: exec_state})
}

var msg_counter = 1;
var execution_counter = 1;
function send(socket, ident, type, content){
    // if(!last_header) last_header = {};

    var reply_header = {
        msg_id: msg_counter++,
        session: last_header.session,
        msg_type: type,
        username: last_header.username
    }
    var signature = '';
    var metadata = {};
    // console.log('!! sending', reply_content)
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