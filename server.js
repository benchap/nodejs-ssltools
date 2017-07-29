var express = require('express');
var opensslTools = require('openssl-cert-tools');
var bodyParser = require('body-parser');
var ssl = require('ssl-utils');
var app = express();
app.use(bodyParser.json()); // support json encoded bodies

app.post('/decode', function (req, res) {
	var cert = unescape(req.body.cert);
	if (cert.indexOf("-BEGIN CERTIFICATE REQUEST-")!==-1) {
	  opensslTools.getCertificateRequestInfo(cert, function(err, data){
		if (err) {
			data.success = "false";
	  	} else {
			data.success = "true";
	 	}
		res.writeHead(200, {"Content-Type": "application/json"});
		res.write(JSON.stringify(data));
		res.end();
	  });
	}
	else if(cert.indexOf("-BEGIN CERTIFICATE-")!==-1) {
		opensslTools.getCertificateInfo(cert, function(err, data){
			if (err) {
				data.success = "false";
			} else {
				data.success = "true";
			}
			res.writeHead(200, {"Content-Type": "application/json"});
			res.write(JSON.stringify(data));
			res.end();
			console.log("-------------- Request completed --------------------\n\n");

		});
 	}
	return;
})


app.post('/verify', function (req, res) {
   	var cert;
	var key;
	var err;
    var data = unescape(req.body.data);

	var regex = /-----BEGIN CERTIFICATE-----([\s\S]*)-----END CERTIFICATE-----/g;
	var result = data.toString().match(regex);
	if(result[0]){
		cert = result[0];
		console.log(cert);
	}else{
		err = "Missing certificate";
	}

	if(!err){
		regex = /-----BEGIN(.*)PRIVATE KEY-----([\s\S]*)-----END(.*)PRIVATE KEY-----/g;		
		result = data.toString().match(regex);
		if(result[0]){
        	key = result[0];
   		}else{
       		err = "Missing key";
   		}
	}

	if(err){
		res.writeHead(200, {"Content-Type": "application/json"});
		res.write({"err": err});
		res.end();
	}else{
    	ssl.verifyCertificateKey(cert,key, function(err,output){
			res.writeHead(200, {"Content-Type": "application/json"});
			res.write(JSON.stringify(output));
			res.end();
    	});
	}
        	
    return;
});

var server = app.listen(8081, function () {
   var host = server.address().address
   var port = server.address().port

   console.log("Example app listening at http://%s:%s", host, port)
});
