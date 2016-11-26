<div id='page-content-wrapper'>
  <div class='container-fluid'>
    <div class='row'>
      <div class="col-md-10 col-md-offset-1">
        <div class="page-header" >
          <h1>SSL Decoder</h1>
        </div>
        <div id='sslform'>
          <form class="form-horizontal">
            <p>This site checks the SSL/TLS configuration of a server. In shows you the full certificate chain, including all kinds of information about every certificate, as well as connection information like ciphersuites and protocol support.</p>
            <p>Fill in either host + port or paste a CSR/Certficiate. Port defaults to 443. <br></p>
            <fieldset>
              <div class="form-group">
                <label class="col-md-1 control-label" for="host">Host </label>  
                <div class="col-md-5">
                  <input id="host" name="host" type="text" placeholder="raymii.org (or Host:IP to test a specific hostname on an IP)" autofocus="autofocus" class="form-control input-md" >
                </div>
                <label class="col-md-1 control-label" for="port">Port</label>  
                <div class="col-md-2">
                  <input id="port" name="port" type="number" placeholder="443" class="form-control input-md">
                </div>
              </div>
              <div class="form-group">
                <div class="col-md-4 col-md-offset-1">
                  <div class="checkbox">
                    <label for="fastcheck">
                      <input type="checkbox" name="fastcheck" id="fastcheck" value="1">
                      Fast check (no connection details, no TLSA check, no certificate transparency submission)
                    </label>
                  </div>
                </div>
              </div>
              <hr>
              <div class="form-group">
                <label class="col-md-1 control-label" for="csr">CSR / Certificate</label>
                <div class="col-md-5">                     
                  <textarea class="form-control" rows=6 id="csr" name="csr" placeholder="Paste a CSR or certificate (in PEM format) here to get all the information in the cert/csr, including the full chain of trust."></textarea>
                </div>
              </div>

              <div class="form-group">
                <div class="col-md-4">
                  <label class="col-md-2 col-md-offset-1 control-label" for="s"></label>
                  <button id="s" name="s" class="btn btn-primary" onsubmit="showElementbyID(true, 'preloader'); showElementbyID(false, 'sslform'); makeRequest('/ssl/?port=' + this.form.port.value + '&csr=' + this.form.csr.value + '&s=&host=' + this.form.host.value,, 'showContent');return false" onclick="showElementbyID(true, 'preloader'); showElementbyID(false, 'sslform'); makeRequest('/ssl/?port=' + this.form.port.value + '&csr=' + this.form.csr.value + '&ciphersuites=' + this.form.ciphersuites.value + '&s=&host=' + this.form.host.value, 'showContent');return false">Submit</button>
                </div>
              </div>
            </fieldset>
          </form>
        </div>
        <div id="preloader">
          <p>
            <img src="<?php echo(htmlspecialchars($current_folder)); ?>img/ajax-loader.gif" />
            <br>&nbsp;<br>
            The SSL Decoder is processing your request. Please wait a few moments.<br>
          </p>
        </div>
        <div id="resultDiv"></div>