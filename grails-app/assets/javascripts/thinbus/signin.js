/**
 * The Login object uses jQuery AJAX and an SRP6JavascriptClientSessionSHA256 object to perform a proof-of-password.
 * See http://simon_massey.bitbucket.org/thinbus/login.png
 */
var Login = {

  /**
   * The following default options may overridden by passing a customer options object into `initialize` method.
   * See http://simon_massey.bitbucket.org/thinbus/login.png
   * @param challengeUrl The URL to do the AJAX lookup to get the user's salt `s` and one-time random server challenge `B`.
   * @param securityCheckUrl The URL to post the password proof.
   * @param emailId The id of the form input field where the user gives their id/email used in the AJAX fetch of the user's salt and challenge.
   * @param passwordId The id of the password field used to compute a proof-of-password with the server one-time challenge and the user's salt.
   * @param formId The form who's onSubmit will run the SRP protocol.
   * @param whitelistFields The fields to post to the server. MUST NOT INCLUDE THE RAW PASSWORD. Some frameworks embed a CSRF token in every form which must be submitted with the form so that hidden field can be whitelisted.
   * @param debugOutput The demo overrides this to output to html in the page.
   */
  options: {
  	 j_s:"",
  	 j_b:"",
     debugOutput: function (msg){
    	 console.log(msg);
     }
  },

  spinOpts: {
	  lines: 9 // The number of lines to draw
	, length: 10 // The length of each line
	, width: 9 // The line thickness
	, radius: 26 // The radius of the inner circle
	, scale: 0.5 // Scales overall size of the spinner
	, corners: 1 // Corner roundness (0..1)
	, color: '#FFF' // #rgb or #rrggbb or array of colors
	, opacity: 0.25 // Opacity of the lines
	, rotate: 0 // The rotation offset
	, direction: 1 // 1: clockwise, -1: counterclockwise
	, speed: 1 // Rounds per second
	, trail: 60 // Afterglow percentage
	, fps: 20 // Frames per second when using setTimeout() as a fallback for CSS
	, zIndex: 2e9 // The z-index (defaults to 2000000000)
	, className: 'spinner' // The CSS class to assign to the spinner
	, top: '50%' // Top position relative to parent
	, left: '50%' // Left position relative to parent
	, shadow: true // Whether to render a shadow
	, hwaccel: false // Whether to use hardware acceleration
	, position: 'absolute' // Element positioning
	},
  initialize: function (options) {
    var me = this;

    if (options) {
      me.options = options;
    }

	me.options.usernameId = '#username-login'
	me.options.passwordId = '#password-login'
	me.options.formId = '#loginForm'
    me.spinner = new Spinner(me.spinOpts)

    $(me.options.formId).on('submit', function (e) {
        var target = document.getElementById('spinner');
        me.spinner.spin(target);

		var loginForm = $(me.options.formId);
		var password = me.getPassword();
		var username = me.getUsername();
		var srpClient = new SRP6JavascriptClientSessionSHA256();
		var start = +(new Date());
		var credentials
		try {
			srpClient.step1(username,password)
			credentials = srpClient.step2(me.options.j_s, me.options.j_b);
			var end = +(new Date());

			var loginForm = $(me.options.formId);

			var values = {
				username: me.getUsername(),
				password: credentials.M1+":"+credentials.A
			};

			$("#set_a").attr("value", credentials.A);
			$("#set_m1").attr("value", credentials.M1);
			$("#password-login").attr("disabled", true);
			//me.options.debugOutput('Client: crypto took ' + (end-start) + 'ms');
			//me.options.debugOutput('Client: ' + JSON.stringify(values) );
			return true

		}catch(e) {
	    	console.log('unexpected programmer error: '+e.message);
	    	//window.location = window.location;
	    	$("#password-login").attr("disabled", false);
	    	$(".btn btn-submit").attr("disabled", false);
	    	me.spinner.stop()
	    	return false
	    }

    });
  },

  getUsername: function () {
	  return $(this.options.usernameId).val();
  },

  getPassword: function () {
    return $(this.options.passwordId).val();
  }

}