var express = require('express');
var opensslTools = require('openssl-cert-tools');
var bodyParser = require('body-parser');
var app = express();
app.use(bodyParser.json()); // support json encoded bodies

app.post('/decode', function (req, res) {
	console.log(unescape(req.body.cert));      // your JSON)
	var cert = unescape(req.body.cert);
	opensslTools.getCertificateRequestInfo(cert, function(err, data){
		if (err) {
			console.log("Decode failed. Reason:",err);
			data.success = "false";
	  	} else {
			console.log("Successfully decoded:",data.subject.CN);
			data.success = "true";
	 	}
		res.writeHead(200, {"Content-Type": "application/json"});
		res.write(JSON.stringify(data));
		res.end();
	});
})

var server = app.listen(8081, function () {
   var host = server.address().address
   var port = server.address().port

   console.log("Example app listening at http://%s:%s", host, port)
})
