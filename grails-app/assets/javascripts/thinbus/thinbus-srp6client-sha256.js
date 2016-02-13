/**
This is the recommended class as it uses the strong hash which 
comes with JDK8 by default. 

You must include config which defines your safe prime constant such as SRP6CryptoParams.N_base10 before loading this file e.g.: 

var SRP6CryptoParams= {
    N_base10: "2176617...
    g_base10: "2",
    k_base16: "5b9e8ef...
}

On a Java server use the matching java class: 

	com.nimbusds.srp6.js.SRP6JavascriptServerSessionSHA256 
	
*/

var SRP6CryptoParams= {
    N_base10 : "52121262640912752964667285632695032600613050183437906127208403954906087528011342749080881964898477780681129487759883265212035813811615469762391060121731614383379392236302640027522575942531705326244439097607152334999641797203369995746049822668215971844691374948743265818455344183370513511212242690839299775637013643294904815730248249184445471199905287979185718349254970604844513822267315026097321150105985689164019973454310120834314656193318576326175421149845690782495893132261664231246852892574888511080864929141487690449264887828243510424107288126138255717083062448158624515428539422718365254959729830166991917902253527411799310663511299549811634873766150932829784217070703102577130844796666758614775407895366825267528329027816220991321833333691036520859244167921294372450202533434697464183209678078285414392137973584746322960634549610697502290397691757273223045460608261352411398449427290086674918939089260542181165063379277031946427052068003417963170393444459872892298251690906019902286138945924540184332512737034985756292318574391183543426904401264425011883353943129657502421306836251647122478935386896736738639930514906599616854243464121833762361589642474953060882856478536623858751386477747032399506253499639883584147066",
	g_base10 : "2",
	k_base16 : "1f108f31bb70bd944efa49b1821ed93218a59dfa17a7bc37b29cdd1645e2ea9f"
}
function SRP6JavascriptClientSessionSHA256(){ }

SRP6JavascriptClientSessionSHA256.prototype = new SRP6JavascriptClientSession();

SRP6JavascriptClientSessionSHA256.prototype.N = function() {
	return new BigInteger(SRP6CryptoParams.N_base10, 10);
}

SRP6JavascriptClientSessionSHA256.prototype.g = function() {
	return new BigInteger(SRP6CryptoParams.g_base10, 10);
}

SRP6JavascriptClientSessionSHA256.prototype.H = function (x) {
		return CryptoJS.SHA256(x).toString().toLowerCase();
}

SRP6JavascriptClientSessionSHA256.prototype.k = new BigInteger(SRP6CryptoParams.k_base16, 16);
