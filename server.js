var express = require('express');
var opensslTools = require('openssl-cert-tools');
var bodyParser = require('body-parser');
var ssl = require('ssl-utils');
var app = express();
app.use(bodyParser.json()); // support json encoded bodies

app.post('/decode', function (req, res) {
	console.log("-------------- Request received --------------------");
	console.log(new Date().toISOString());
	console.log("method ",req.method);
	console.log("Certificate received:\n",unescape(req.body.cert));      // your JSON)
	var cert = unescape(req.body.cert);
	if (cert.indexOf("-BEGIN CERTIFICATE REQUEST-")!==-1) {
	  opensslTools.getCertificateRequestInfo(cert, function(err, data){
		if (err) {
			console.log("Decode failed. Reason:",err);
			data.success = "false";
	  	} else {
			console.log("Successfully decoded csr:",data.subject.CN);
			data.success = "true";
	 	}
		res.writeHead(200, {"Content-Type": "application/json"});
		res.write(JSON.stringify(data));
		res.end();
		console.log("-------------- Request completed --------------------\n\n");
	  });
	}
	else if(cert.indexOf("-BEGIN CERTIFICATE-")!==-1) {
		opensslTools.getCertificateInfo(cert, function(err, data){
			if (err) {
				console.log("Decode failed. Reason:",err);
				data.success = "false";
			} else {
		    	console.log(data);
				console.log("Successfully decoded cert:",data.subject.CN);
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
		console.log("2");
		console.log(data);
		result = data.toString().match(regex);
		if(result[0]){
        	key = result[0];
       		console.log(key);
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
    	    if(err){
        	    console.log("Error: ",err);
        	}else{
        	    console.log(output);
        	}
			res.writeHead(200, {"Content-Type": "application/json"});
			res.write(JSON.stringify(output));
			res.end();

        	console.log("--------------Verify Request completed --------------------\n\n");
    	});
	}
        	
    return;
});

var server = app.listen(8081, function () {
   var host = server.address().address
   var port = server.address().port

   console.log("Example app listening at http://%s:%s", host, port)
});
