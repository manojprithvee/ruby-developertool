<?php
error_reporting(E_ALL & ~E_NOTICE);

$gets = explode('&', $argv[1]);
foreach($gets as $g)
{
$g = explode('=', $g);
$_GET[$g[0]] = $g[1];
}


function submitCertToCT($chain, $ct_url) {
  global $timeout;
  $ct_chain = array('chain' => []);
  foreach ($chain as $key => $value) {
    $string = $value['key']['certificate_pem'];
    $pattern = '/-----(.*)-----/';
    $replacement = '';
    $string = preg_replace($pattern, $replacement, $string);
    $pattern = '/\n/';
    $replacement = '';
    $string = preg_replace($pattern, $replacement, $string);
    array_push($ct_chain['chain'], $string);    
  }
  $post_data = json_encode($ct_chain);
  $ch = curl_init();  
  curl_setopt($ch, CURLOPT_URL, $ct_url . "/ct/v1/add-chain");
  curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
  curl_setopt($ch, CURLOPT_NOBODY, true);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_FAILONERROR, false);
  curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
  curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
  curl_setopt($ch, CURLOPT_HEADER, false); 
  curl_setopt($ch, CURLOPT_POST, count($post_data));
  curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);    
  $ct_output = curl_exec($ch);
  curl_close($ch);
  return $ct_output;
}

function fixed_gethostbyname($host) {
  $ips = dns_get_record($host, DNS_A + DNS_AAAA);
  sort($ips);
  foreach ($ips as $key => $value) {
    if ($value['type'] === "AAAA") {
      $ip = $value['ipv6'];
    } elseif ($value['type'] === "A") {
      $ip = $value['ip'];
    } else {
      return false;
    }
  }
  if ($ip != $host) { 
    return $ip; 
  } else {
    return false;
  }
}

function get(&$var, $default=null) {
  return isset($var) ? $var : $default;
}

function server_http_headers($host, $ip, $port){
  global $timeout;
  // first check if server is http. otherwise long timeout.
  // sometimes fails cloudflare with
  // error:14077438:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert internal error
  $ch = curl_init(("https://" . $ip . ":" . $port));
  curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
  curl_setopt($ch, CURLOPT_NOBODY, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array("Host: $host"));
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_FAILONERROR, true);
  curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
  curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
  if(curl_exec($ch) === false) {
      if(curl_errno($ch) != 35) {
      curl_close($ch);
      return false;
    }
  }
  curl_close($ch);

  stream_context_set_default(
    array("ssl" => 
      array("verify_peer" => false,
        "capture_session_meta" => true,
        "verify_peer_name" => false,
        "peer_name" => $host,
        "allow_self_signed" => true,
        "sni_enabled" => true),
      'http' => array(
        'method' => 'GET',
        'max_redirects' => 1,
        'header' => 'Host: '.$host,
        'timeout' => $timeout
        )
      )
    );
  $headers = get_headers("https://$ip:$port", 1);
  //pre_dump($headers);
  if (!empty($headers)) {
    $headers = array_change_key_case($headers, CASE_LOWER);
    return $headers;
  }
}

function ssl_conn_ciphersuites($host, $ip, $port, $ciphersuites) {
  global $timeout;
  $old_error_reporting = error_reporting();
  error_reporting(0); 
  $results = array();
  foreach ($ciphersuites as $value) {
    $results[$value] = false;
    $stream = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "verify_peer_name" => false,
      "allow_self_signed" => true,
      "peer_name" => $host,
      'ciphers' => $value,
      "sni_enabled" => true)));
    $read_stream = stream_socket_client("ssl://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream);
    if ( $read_stream === false ) {
      $results[$value] = false;
    } else {
      $results[$value] = true;
    }
  }
  error_reporting($old_error_reporting);
  return $results;
}

function test_heartbleed($ip, $port) {
  //this uses an external python2 check to test for the heartblead vulnerability
  global $current_folder;
  global $timeout;
  $exitstatus = 0;
  $output = 0;
  $cmdexitstatus = 0;
  $cmdoutput = 0;
  $result = 0;
  $uuid = gen_uuid();
  $tmpfile = "/tmp/" . $uuid . ".txt";
  # check if python2 is available
  exec("command -v python2 >/dev/null 2>&1", $cmdoutput, $cmdexitstatus);
  if ($cmdexitstatus != 1) {
    //15 is a reasonable timeout. 
    exec("timeout 15 python2 " . getcwd() . "/inc/heartbleed.py " . escapeshellcmd($ip) . " --json \"" . $tmpfile . "\" --threads 1 --port " . escapeshellcmd($port) . " --silent", $output, $exitstatus);
    if (file_exists($tmpfile)) {
      $json_data = json_decode(file_get_contents($tmpfile),true);
      foreach ($json_data as $key => $value) {
        if ($value['status'] == true) {
          $result = "vulnerable";
        } else {
          $result = "not_vulnerable";
        }
      }
      unlink($tmpfile);
    }
  } else {
    $result = "python2error";
  }
  return $result;
}

function heartbeat_test($host, $port) {
  //this tests for the heartbeat protocol extension
  global $random_blurp;
  global $timeout;
  $result = 0;

  $output = shell_exec('echo | timeout ' . $timeout . ' openssl s_client -connect ' . escapeshellcmd($host) . ':' . escapeshellcmd($port) . ' -servername ' . escapeshellcmd($host) . ' -tlsextdebug 2>&1 </dev/null | awk -F\" \'/server extension/ {print $2}\'');

  $output = preg_replace("/[[:blank:]]+/"," ", $output);
  $output = explode("\n", $output);
  $output = array_map('trim', $output);
  if ( in_array("heartbeat", $output) ) {
    $result = 1;
  }
  return $result;
}

function test_sslv2($ip, $port) {
  global $timeout;
  $exitstatus = 0;
  $output = 0;
  exec('echo | timeout ' . $timeout . ' openssl s_client -connect "' . escapeshellcmd($ip) . ':' . escapeshellcmd($port) . '" -ssl2 2>&1 >/dev/null', $output, $exitstatus); 
  if ($exitstatus == 0) { 
    $result = true;
  } else {
    $result = false;
  }
  return $result;
}

function conn_compression($host, $ip, $port) {
  global $timeout;
  // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
  //if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
  //  return true;
  //}
  $exitstatus = 0;
  $output = 0;
  if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    exec('echo | timeout ' . $timeout . ' openssl s_client -servername "' . escapeshellcmd($host) . '" -connect "' . $ip . ':' . escapeshellcmd($port) . '" -status -tlsextdebug 2>&1 | grep -qe "^Compression: NONE"', $output, $exitstatus); 
  } else {
    exec('echo | timeout ' . $timeout . ' openssl s_client -servername "' . escapeshellcmd($host) . '" -connect "' . escapeshellcmd($ip) . ':' . escapeshellcmd($port) . '" -status -tlsextdebug 2>&1 | grep -qe "^Compression: NONE"', $output, $exitstatus); 
  }
  if ($exitstatus == 0) { 
    $result = false;
  } else {
    $result = true;
  }
  return $result;
}

function ssl_conn_protocols($host, $ip, $port) {
  global $timeout;
  $old_error_reporting = error_reporting();
  error_reporting(0); 
  $results = array('sslv2' => false, 
                   'sslv3' => false, 
                   'tlsv1.0' => false,
                   'tlsv1.1' => false,
                   'tlsv1.2' => false);

  $results['sslv2'] = test_sslv2($host, $port);

  $stream_sslv3 = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "capture_session_meta" => true,
      "verify_peer_name" => false,
      "peer_name" => $host,
      "allow_self_signed" => true,
      'crypto_method' => STREAM_CRYPTO_METHOD_SSLv3_CLIENT,
      "sni_enabled" => true)));
  $read_stream_sslv3 = stream_socket_client("sslv3://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_sslv3);
  if ( $read_stream_sslv3 === false ) {
    $results['sslv3'] = false;
  } else {
    $results['sslv3'] = true;
  }

  $stream_tlsv10 = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "capture_session_meta" => true,
      "verify_peer_name" => false,
      "peer_name" => $host,
      "allow_self_signed" => true,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_0_CLIENT,
      "sni_enabled" => true)));
  $read_stream_tlsv10 = stream_socket_client("tlsv1.0://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_tlsv10);
  if ( $read_stream_tlsv10 === false ) {
    $results['tlsv1.0'] = false;
  } else {
    $results['tlsv1.0'] = true;
  }

  $stream_tlsv11 = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "capture_session_meta" => true,
      "verify_peer_name" => false,
      "allow_self_signed" => true,
      "peer_name" => $host,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_1_CLIENT,
      "sni_enabled" => true)));
  $read_stream_tlsv11 = stream_socket_client("tlsv1.1://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_tlsv11);
  if ( $read_stream_tlsv11 === false ) {
    $results['tlsv1.1'] = false;
  } else {
    $results['tlsv1.1'] = true;
  }

  $stream_tlsv12 = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "capture_session_meta" => true,
      "verify_peer_name" => false,
      "allow_self_signed" => true,
      "peer_name" => $host,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_2_CLIENT,
      "sni_enabled" => true)));
  $read_stream_tlsv12 = stream_socket_client("tlsv1.2://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_tlsv12);
  if ( $read_stream_tlsv12 === false ) {
    $results['tlsv1.2'] = false;
  } else {
    $results['tlsv1.2'] = true;
  }
  error_reporting($old_error_reporting);
  return $results;
}

function get_ca_issuer_urls($raw_cert_data) {
  $result = array();
  $authorityInfoAcces = explode("\n", openssl_x509_parse($raw_cert_data)['extensions']['authorityInfoAccess']);
  if (openssl_x509_parse($raw_cert_data)['extensions']['authorityInfoAccess']) {
    foreach ($authorityInfoAcces as $authorityInfoAccess) {
      $crt_uris = explode("CA Issuers - URI:", $authorityInfoAccess);
      foreach ($crt_uris as $key => $crt_uri) {
        foreach (explode("\n", $crt_uri) as $crt_ur) {
          if($crt_ur) {
            if (strpos(strtolower($crt_ur), 'ocsp') === false) {
              array_push($result, $crt_ur);
            }  
          }                
        }
      }
    }
  }
  return $result;
}

function get_ca_issuer_crt($raw_cert_data) {
  //we save certs, so we might have the issuer already.
  //first check that, otherwise get crt from authorityinfoaccess
  global $timeout;
  if (!is_dir('crt_hash')) {
    mkdir('crt_hash');
  }
  // filenames of saved certs are hashes of the asort full subject. 
  $sort_subject = openssl_x509_parse($raw_cert_data)['issuer'];
  asort($sort_subject);
  foreach ($sort_subject as $key => $value) {
    $issuer_full = "/" . $key . "=" . $value . $issuer_full;
  }
  $crt_check_hash = hash("sha256", $issuer_full);
  $crt_check_hash_folder = "crt_hash/";
  $crt_check_hash_file = $crt_check_hash_folder . $crt_check_hash . ".pem";
  echo "\n<!-- " . htmlspecialchars($issuer_full) . "\n" . $crt_check_hash_file . " -->\n";
  if(file_exists($crt_check_hash_file)) {
    //if we already have a PEM file where the subject matches this certs issuer
    //it probably is the correct one. return that and be done with it.
    $crt_data = file_get_contents($crt_check_hash_file);
    $export_pem = "";
    openssl_x509_export($crt_data, $export_pem);
    //make sure it is valid data.
    if($export_pem) {
      $crt_cn = openssl_x509_parse($crt_data)['name'];
      //add start and end for more clarity since this is a copy-pastable thingy.
      $return_crt = "#start " . $crt_cn . "\n" . $export_pem . "#end " . $crt_cn . "\n";
      return $return_crt;
    }
  } else {
    $issuer_urls = get_ca_issuer_urls($raw_cert_data);
    if($issuer_urls) {
      foreach ($issuer_urls as $key => $ca_issuer_url) {
        //if we don't have that cert saved, we check if there is a der file
        //based on the issuer url hash.
        $crt_hash = hash("sha256", $ca_issuer_url);
        $crt_hash_folder = "crt_hash/";
        $crt_hash_file = $crt_hash_folder . $crt_hash . ".der";
        echo "\n<!-- " . htmlspecialchars($ca_issuer_url) . "\n" . $crt_hash_file . " -->\n";
        if (!file_exists($crt_hash_file)) {
          //that file is not there, let's get it
          if (0 === strpos($ca_issuer_url, 'http')) {
            $fp = fopen ($crt_hash_file, 'w+');
            $ch = curl_init(($ca_issuer_url));
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_FILE, $fp);
            curl_setopt($ch, CURLOPT_FAILONERROR, true);
            curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
            if(curl_exec($ch) === false) {
              continue;
            }
            curl_close($ch);
            if(stat($crt_hash_file)['size'] < 10 ) {
              //probably a corrypt file. sould be at least +100KB.
                unlink($crt_hash_file);
            }
          }
        } else {
          if (time()-filemtime($crt_hash_file) > 5 * 84600) {
            // file older than 5 days. crt might have changed, retry.
              $content_hash = sha1_file($crt_hash_file);
              rename($crt_hash_file, $crt_hash_folder . $content_hash . ".content_hash.der");
              get_ca_issuer_crt($raw_cert_data);
          }
        }
        if (file_exists($crt_hash_file)) {
          //we have a a der file, we need to convert it to pem and return it.
          //dirty way to get pem from der...
          $crt_data = "-----BEGIN CERTIFICATE-----\n" . wordwrap(base64_encode(file_get_contents($crt_hash_file)), 65, "\n", 1) . "\n-----END CERTIFICATE-----";
          $crt_cn = openssl_x509_parse($crt_data)['name'];
          $export_pem = "";
          openssl_x509_export($crt_data, $export_pem);
          //make sure it is valid data.
          if($export_pem) {
            $return_crt = "#start " . $crt_cn . "\n" . $export_pem . "\n#end " . $crt_cn . "\n";
            //add start and end for more clarity since this is a copy-pastable thingy.
            $sort_subject = openssl_x509_parse($crt_data)['subject'];
            asort($sort_subject);
            foreach ($sort_subject as $key => $value) {
              $name_full = "/" . $key . "=" . $value . $name_full;
            }
            $crt_hash = hash("sha256", $name_full);
            $crt_hash_folder = "crt_hash/";
            $crt_hash_file = $crt_hash_folder . $crt_hash . ".pem";
            //if the chain is wrong and we got this certificate
            //via the authorityinfoaccess, we might not get it as a 
            //regular cert via the check. so therefore we save this 
            //as well, via the same mechanism.
            if(file_exists($crt_hash_file)) {
              if (time()-filemtime($crt_hash_file) > 5 * 84600) {
                // file older than 5 days. crt might have changed, retry.
                $content_hash = sha1_file($crt_hash_file);
                rename($crt_hash_file, $crt_hash_folder . $content_hash . ".content_hash.pem");
                file_put_contents($crt_hash_file, $export_pem);
              }
            } else {
              file_put_contents($crt_hash_file, $export_pem);
            }
            if(stat($crt_hash_file)['size'] < 10 ) {
              //probably a corrypt file. sould be at least +100KB.
              unlink($crt_hash_file);
            }
          }
        }
        return $return_crt;
      }            
    }
  }
}


function get_issuer_chain($raw_cert_data, $number=1, $result=null) {
  global $max_chain_length;
  if ($result['complete'] == 'yes') {
    return $result;
  }
  if ($number > $max_chain_length) {
    $result['complete'] == 'error';
    return $result;
  }
  $number += 1;

  if (!is_array($result)) {
    $result = array('certs' => array(), 'complete' => 'false');
  }

  $sort_subject = openssl_x509_parse($raw_cert_data)['subject'];
  asort($sort_subject);
  foreach ($sort_subject as $key => $value) {
    $subject_full = "/" . $key . "=" . $value . $subject_full;
  }
  $sort_issuer = openssl_x509_parse($raw_cert_data)['issuer'];
  asort($sort_issuer);
  foreach ($sort_issuer as $key => $value) {
    $issuer_full = "/" . $key . "=" . $value . $issuer_full;
  }
  if($issuer_full == $subject_full && $result) {
    $result['complete'] == 'yes';
    return $result;
  } 
  $this_issuer = get_ca_issuer_crt($raw_cert_data);
  if($this_issuer) {
    array_push($result['certs'], $this_issuer);
    $result = get_issuer_chain($this_issuer, $number, $result);
    return $result;
  } else {
    return $result;
  }
  return $result;
}

function ssl_conn_metadata($data,$fastcheck=0) {
  global $random_blurp;
  global $current_folder;
  $chain_length = count($data["chain"]);
  echo "<section id='conndata'>";
  if (is_array($data["warning"]) && count($data["warning"]) >= 1) {
    $data["warning"] = array_unique($data["warning"]);
    if (count($data["warning"]) == 1) {
      echo "<h3>" . count($data["warning"]) . " warning!</h3>";
    } else {
      echo "<h3>" . count($data["warning"]) . " warnings!</h3>";
    }
    foreach ($data["warning"] as $key => $value) {
      echo "<div class='alert alert-danger' role='alert'>";
      echo $value;
      echo "</div>";
    }
  }
  echo "<table class='table table-striped table-bordered'>";
  echo "<tbody>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Connection Data</strong></td>";
  echo "</tr>";
  echo "<tr>";
  // chain
  echo "<td>Chain sent by Server <br>(in server order)</td>";
  echo "<td style='font-family: monospace;'>";
  foreach ($data["chain"] as $key => $value) {
    if (!empty($value['name'])) {
      echo "Name...........: <i>";
      echo htmlspecialchars(htmlspecialchars($value['name']));
      echo " </i><br>Issued by......:<i> ";
      echo htmlspecialchars(htmlspecialchars($value['issuer']));
      echo "</i><br>";
    }
    if (isset($value["error"])) {
      echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Error: Issuer does not match the next certificate CN. Chain order is probably wrong.</span><br><br>";
    }
  }
  echo "<br>";
  if ($data["validation"]["status"] == "failed") {
    echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Validating certificate chain failed:</span><br>";
    echo "<pre>";
    echo htmlspecialchars($data["validation"]["error"]);
    echo "</pre>";
  } else {
    echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>Successfully validated certificate chain.</span><br>";
  }
  echo "</td>";
  echo "</tr>";

  // correct chain
  if ($fastcheck == 0 && $data["validation"]["status"] == "failed" && is_array($data["validation"]["correct_chain"])) {
    echo "<tr>";
    echo "<td><strong>Correct Chain</strong></td>";
    echo "<td>";
    echo "<p><strong>The validation of this certificate failed. This might be because of an incorrect or incomplete CA chain. Based on the '<code>authorityInfoAccess</code>' extension and earlier saved certificates, the below result probably contains the correct CA Chain, in the correct order, for this certificate. The result also contains your certificate as the first one.</strong><br>";

    echo "<p>This is our best guess at the correct ca signing chain: <br><ul>";
    foreach ($data['validation']['cns'] as $cn_key => $cn_value) {
      foreach ($cn_value as $cnn_key => $cnn_value) {
        echo "<span style='font-family: monospace;'><li>";
        if($cnn_key == 'cn') {
          echo "Name.......: ";
          echo htmlspecialchars($cnn_value);
          echo "</li></span>  ";
        }
        if ($cnn_key == 'issuer') {
          echo "Issued by..: ";
          echo htmlspecialchars($cnn_value);
          echo "</li></span><br>";
        }
      }
    }
    echo "</ul></p>";
    echo "<p>Click below to see the full chain output in PEM format, copy-pastable in most software.</p>";
    ?>
    <div class="panel-group" id="accordion-correct-chain" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="heading-correct-chain">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#collapse-correct-chain" aria-expanded="false" aria-controls="collapse-correct-chain">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="collapse-correct-chain" class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading-correct-chain">
          <div class="panel-body">
    <?php
    echo "<pre>"; 
    foreach ($data['validation']['correct_chain'] as $cert) {
      echo htmlspecialchars($cert);
      echo "<br>";
    }
    echo "</pre>"; 
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";
  }

  // ip hostname port
  if ( $data["hostname"] ) {
    echo "<tr>";
    echo "<td>IP / Hostname / Port</td>";
    echo "<td>";
    echo htmlspecialchars($data["ip"]);
    echo " - ";
    echo htmlspecialchars($data["hostname"]);
    echo " - ";
    echo htmlspecialchars($data["port"]);
    echo "</td>";
    echo "</tr>";
  }
  if($fastcheck == 0) {
    // protocols
    echo "<tr>";
    echo "<td>Protocols</td>";
    echo "<td>";
    $protocols = $data["protocols"];
    foreach ($protocols as $key => $value) {
      if ( $value == true ) {
        if ( $key == "tlsv1.2") {
          echo '<p><span class="text-success glyphicon glyphicon-ok"></span> - <span class="text-success">TLSv1.2 (Supported)</span></p>';
        } else if ( $key == "tlsv1.1") {
          echo '<p><span class="glyphicon glyphicon-ok"></span> - TLSv1.1 (Supported)</p>';
        } else if ( $key == "tlsv1.0") {
          echo '<p><span class="glyphicon glyphicon-ok"></span> - TLSv1.0 (Supported)</p>';
        } else if ( $key == "sslv3") {
          echo '<p><span class="text-danger glyphicon glyphicon-ok"></span> - <span class="text-danger">SSLv3 (Supported) </span>';
          echo "<a href='https://blog.mozilla.org/security/2014/10/14/the-poodle-attack-and-the-end-of-ssl-3-0/' data-toggle='tooltip' data-placement='top' title='SSLv3 is old and broken. It makes you vulerable for the POODLE attack. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
        } else if ( $key == "sslv2") {
          echo '<p><span class="text-danger glyphicon glyphicon-ok"></span> - <span class="text-danger">SSLv2 (Supported) </span>';
          echo "<a href='http://www.rapid7.com/db/vulnerabilities/sslv2-and-up-enabled' data-toggle='tooltip' data-placement='top' title='SSLv2 is old and broken. It was replaced by SSLv3 in 1996. It does not support intermediate certs and has flaws in the crypto. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
        } else {
          echo '<p><span class="glyphicon glyphicon-ok"></span> - <span>'.$key.' (Supported)</span></p>';
        }
      } else {
        if ( $key == "tlsv1.2") {
          echo '<p><span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">TLSv1.2 (Not supported)</span> ';
          echo "<a href='http://www.yassl.com/yaSSL/Blog/Entries/2010/10/7_Differences_between_SSL_and_TLS_Protocol_Versions.html' data-toggle='tooltip' data-placement='top' title='TLSv1.2 was released in 2008. It is the most recent and secure version of the protocol. It adds TLS extensions and the AES ciphersuites plus other features and fixes. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
        } else if ( $key == "tlsv1.1") {
          echo '<p><span class="glyphicon glyphicon-remove"></span> - TLSv1.1  (Not supported)</p>';
        } else if ( $key == "tlsv1.0") {
          echo '<p><span class="glyphicon glyphicon-remove"></span> - TLSv1.0  (Not supported)</p>';
        } else if ( $key == "sslv3") {
          echo '<p><span class="text-success glyphicon glyphicon-remove"></span> - <span class="text-success">SSLv3 (Not supported)</span></p>';
        } else if ( $key == "sslv2") {
          echo '<p><span class="text-success glyphicon glyphicon-remove"></span> - <span class="text-success">SSLv2 (Not supported)</span></p>';
        } else {
          echo '<p><span class="glyphicon glyphicon-remove"></span> - <span>'.$key.'(Not supported)</span></p>';
        }
      }
    }
    echo "</td>";
    echo "</tr>";
    echo "<tr>";
    echo "<td>SSL Compression</td>";
    echo "<td>";
    if ($data['compression'] == false) {
      echo '<p><span class="text-success glyphicon glyphicon-ok"></span> - <span class="text-success">SSL Compression disabled</span></p>';
    } else {
      echo '<p><span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">SSL Compression enabled</span> ';

      echo "<a href='https://isecpartners.com/blog/2012/september/details-on-the-crime-attack.aspx' data-toggle='tooltip' data-placement='top' title='SSL Compression makes you vulnerable to the CRIME attack. Click the question mark for more info about it.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
    }
    echo "</td>";
    echo "</tr>";
    //ciphersuites
    echo "<tr>";
    echo "<td>Ciphersuites supported by server</td>";
    echo "<td>";
    $bad_ciphersuites = array('ECDHE-RSA-DES-CBC3-SHA',
      'ECDHE-ECDSA-DES-CBC3-SHA',
      'EDH-RSA-DES-CBC3-SHA',
      'EDH-DSS-DES-CBC3-SHA',
      'DH-RSA-DES-CBC3-SHA',
      'DH-DSS-DES-CBC3-SHA',
      'ECDH-RSA-DES-CBC3-SHA',
      'ECDH-ECDSA-DES-CBC3-SHA',
      'DES-CBC3-SHA',
      'EDH-RSA-DES-CBC-SHA',
      'EDH-DSS-DES-CBC-SHA',
      'DH-RSA-DES-CBC-SHA',
      'DH-DSS-DES-CBC-SHA',
      'DES-CBC-SHA',
      'EXP-EDH-RSA-DES-CBC-SHA',
      'EXP-EDH-DSS-DES-CBC-SHA',
      'EXP-DH-RSA-DES-CBC-SHA',
      'EXP-DH-DSS-DES-CBC-SHA',
      'EXP-DES-CBC-SHA',
      'EXP-EDH-RSA-DES-CBC-SHA',
      'EXP-EDH-DSS-DES-CBC-SHA',
      'EXP-DH-RSA-DES-CBC-SHA',
      'EXP-DH-DSS-DES-CBC-SHA',
      'EXP-DES-CBC-SHA',
      'EXP-RC2-CBC-MD5',
      'EXP-RC4-MD5',
      'RC4-MD5',
      'EXP-RC2-CBC-MD5',
      'EXP-RC4-MD5',
      'ECDHE-RSA-RC4-SHA',
      'ECDHE-ECDSA-RC4-SHA',
      'ECDH-RSA-RC4-SHA',
      'ECDH-ECDSA-RC4-SHA',
      'RC4-SHA',
      'RC4-MD5',
      'PSK-RC4-SHA',
      'EXP-RC4-MD5',
      'ECDHE-RSA-NULL-SHA',
      'ECDHE-ECDSA-NULL-SHA',
      'AECDH-NULL-SHA',
      'RC4-SHA',
      'RC4-MD5',
      'ECDH-RSA-NULL-SHA',
      'ECDH-ECDSA-NULL-SHA',
      'NULL-SHA256',
      'NULL-SHA',
      'NULL-MD5');
    foreach ($data["supported_ciphersuites"] as $key => $value) {
      if (in_array($value, $bad_ciphersuites)) {
        $bad_ciphersuite = 1;
        echo "<span class='text-danger glyphicon glyphicon-remove'></span>";
        echo "<span class='text-danger'> ";
        echo htmlspecialchars($value);
        echo "</span>";
      } else {
        echo "<span class='glyphicon glyphicon-minus'></span> ";
        echo htmlspecialchars($value);
      }
      echo "<br>";
    }
    if ($bad_ciphersuite) {
      echo "<p><br>Ciphersuites containing <a href='https://en.wikipedia.org/wiki/Null_cipher'>NULL</a>,";
      echo " <a href='https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States'>EXP(ort)</a>,";
      echo " <a href='https://en.wikipedia.org/wiki/Weak_key'>DES";
      echo " and RC4</a> are marked RED because they are suboptimal.</p>";
    }
    echo "</td>";
    echo "</tr>";
    //tls fallback scsv
    echo "<tr>";
    echo "<td>";
    echo "TLS_FALLBACK_SCSV";
    echo "</td>";
    echo "<td>";

    if ($data["tls_fallback_scsv"] == "supported") {
      echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>TLS_FALLBACK_SCSV supported. </span>";
    } elseif ($data["tls_fallback_scsv"] == "unsupported") {
      echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>TLS_FALLBACK_SCSV not supported. </span>";
    } else {
      echo "Only 1 protocol enabled, fallback not possible, TLS_FALLBACK_SCSV not required. ";
    }
    echo "<a href='http://googleonlinesecurity.blogspot.nl/2014/10/this-poodle-bites-exploiting-ssl-30.html' data-toggle='tooltip' data-placement='top' title='TLS_FALLBACK_SCSV provides protocol downgrade protection. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a>";
    echo "</td>";
    echo "</tr>";

    //heartbleed
    if ($data['heartbleed'] != 'python2error') {
      echo "<tr>";
      echo "<td>";
      echo "Heartbleed";
      echo "</td>";
      echo "<td>";

      if ($data["heartbleed"] == "not_vulnerable") {
        echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>Not vulnerable. </span>";
      } elseif ($data["heartbleed"] == "vulnerable") {
        echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Vulnerable. </span>";
      } 
      echo "<a href='http://heartbleed.com/' data-toggle='tooltip' data-placement='top' title='Heartbleed is a serious vulnerability exposing server memory and thus private data to an attacker. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a>";
      echo "</td>";
      echo "</tr>";
    }

    echo "<tr>";
    echo "<td>";
    echo "Heartbeat Extension";
    echo "</td>";
    echo "<td>";

    if ($data["heartbeat"] == "1") {
      echo "Extension enabled.";
    } else {
      echo "Extenstion not enabled.";
    } 
    echo "</td>";
    echo "</tr>";

    // headers
    echo "<tr>";
    echo "<td>";
    echo "<a href='https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html'>Strict Transport Security</a>";
    echo "</td>";
    echo "<td>";
    // hsts
    if ( $data["strict_transport_security"] == "not set" ) {
      echo '<span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">Not Set</span>';
    } else {
      echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>";
      echo htmlspecialchars($data["strict_transport_security"]);
      echo "</span>";
    }
    echo " <a href='https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html' data-toggle='tooltip' data-placement='top' title='Strict Transport Security lets visitors know that your website should only be visited via HTTPS. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a>";
    echo "</td>";
    echo "</tr>";
    echo "<tr>";
    echo "<td>";
    echo "<a href='https://raymii.org/s/articles/HTTP_Public_Key_Pinning_Extension_HPKP.html'>HTTP Public Key Pinning Extension (HPKP)</a>";
    echo "</td>";
    echo "<td>";
    //hpkp
    if ( $data["public_key_pins"] == "not set" ) {
      echo '<span>Not Set</span>';
    } else {
      echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>";
      echo htmlspecialchars($data["public_key_pins"]);
    }
    if ( $data["public_key-pins_report_only"] ) {
      echo "<b>Report Only</b>: ";
      echo htmlspecialchars($data["public_key_pins_report_only"]);
    }

    echo "</td>";
    echo "</tr>";
    // ocsp stapling
    echo "<tr>";
    echo "<td>OCSP Stapling</td>";
    echo "<td>";
    if (isset($data["ocsp_stapling"]["working"])) {
      if($data["ocsp_stapling"]["working"] == 1) {
        echo "<table class='table'>";
        foreach ($data["ocsp_stapling"] as $key => $value) {
          if ($key != "working") {
            echo "<tr><td>" . htmlspecialchars(ucfirst(str_replace('_', ' ', $key))) . "</td><td>" . htmlspecialchars($value) . "</td></tr>";
          }
        } 
        echo "</table>";
      } else {
        echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>No OCSP stapling response received.</span>";
      }
    } else {
      echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>No OCSP stapling response received.</span>";
    }
    echo "</td>";
  }
  // openssl version
  echo "</tr>";
  echo "<tr>";
  echo "<td>This Server's OpenSSL Version</td>";
  echo "<td>";
  echo htmlspecialchars(shell_exec("openssl version"));
  echo "</td>";
  echo "</tr>";
  echo "<tr>";
  //date
  echo "<td>This Server's Date <br>(RFC 2822)</td>";
  echo "<td>";
  echo htmlspecialchars(shell_exec("date --rfc-2822"));
  echo "</td>";
  echo "</tr>";
  echo "</tbody>";
  echo "</table>";
}

function ssl_conn_metadata_json($host, $ip, $port, $read_stream, $chain_data=null,$fastcheck=0) {
  $result = array();
  global $random_blurp;
  global $current_folder;
  global $timeout;
  global $max_chain_length;
  $context = stream_context_get_params($read_stream);
  $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];
  $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"])[0];
  // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
  // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )) {
  //   $result["warning"][] = "You are testing an IPv6 host. Due to <a href=\"https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest\">bugs</a> in OpenSSL's command line tools the results will be inaccurate. Known incorrect are OCSP Stapling, TLS_FALLBACK_SCSV and SSL Compression results, others may also be incorrect.";
  // } 
  
  $result["checked_hostname"] = $host;
  //chain
  if (isset($context_meta)) { 
    if (isset($chain_data)) {
      $chain_length = count($chain_data);
      $certificate_chain = array();
      if ($chain_length <= 10) {
        for ($i = 0; $i < $chain_length; $i++) {
          if (openssl_x509_parse($chain_data[$i])['issuer']['CN'] && openssl_x509_parse($chain_data[$i])['subject']['CN']) {
            $result["chain"][$i]["name"] = openssl_x509_parse($chain_data[$i])['subject']['CN'];
            $result["chain"][$i]["issuer"] = openssl_x509_parse($chain_data[$i])['issuer']['CN'];
            $export_pem = "";
            openssl_x509_export($chain_data[$i], $export_pem);
            array_push($certificate_chain, $export_pem);
            if (openssl_x509_parse($chain_data[$i])['issuer']['CN'] == openssl_x509_parse($chain_data[$i + 1])['subject']['CN']){
              continue;
            } else {
              if ($i != $chain_length - 1) {
                $result["chain"][$i]["error"] = "Issuer does not match the next certificate CN. Chain order is probably wrong.";
                $result["warning"][] = "Issuer does not match the next certificate CN. Chain order is probably wrong.";
              }
            }
          }
        }
      } 
      // chain validation
      file_put_contents('/tmp/verify_cert.' . $random_blurp . '.pem', implode("\n", array_reverse($certificate_chain)).PHP_EOL , FILE_APPEND);
      $verify_output = 0;
      $verify_exit_code = 0;
      $verify_exec = exec(escapeshellcmd('openssl verify -verbose -purpose any -CAfile ' . getcwd() . '/cacert.pem /tmp/verify_cert.' . $random_blurp . '.pem') . "| grep -v OK", $verify_output, $verify_exit_code);

      if ($verify_exit_code != 1) {
        $result["validation"]["status"] = "failed";
        $result["validation"]["error"] = "Error: Validating certificate chain failed: " . str_replace('/tmp/verify_cert.' . $random_blurp . '.pem: ', '', implode("\n", $verify_output));
        $result["warning"][] = "Validating certificate chain failed. Probably non-trusted root/self signed certificate, or the chain order is wrong.";
      } else {
        $result["validation"]["status"] = "success";
      }
      unlink('/tmp/verify_cert.' . $random_blurp . '.pem');
    }

    //chain construction
    if (isset($chain_data) && $factcheck == 0 && $result["validation"]["status"] == "failed") {
      $return_chain = array();
      $export_pem = "";
      openssl_x509_export($chain_data[0], $export_pem);
      $crt_cn = openssl_x509_parse($chain_data[0])['name'];
      $export_pem = "#start " . $crt_cn . "\n" . $export_pem . "\n#end " . $crt_cn . "\n";
      array_push($return_chain, $export_pem);
      $chain_length = count($chain_data);
      $certificate_chain = array();
      if ($chain_length <= $max_chain_length) {
        $issuer_crt = get_issuer_chain($chain_data[0]);
        if (count($issuer_crt['certs']) >= 1) {
          $issuercrts = array_unique($issuer_crt['certs']);
          foreach ($issuercrts as $key => $value) {
            array_push($return_chain, $value);
          }
        }
      }
    }
    if(is_array($return_chain)) {
      $return_chain = array_unique($return_chain);
    }
    if(count($return_chain) > 1) {
      $result["validation"]["cns"] = array();
      $result["correct_chain"]["cns"] = array();
      $crt_cn = array();
      foreach ($return_chain as $retc_key => $retc_value) {
        $issuer_full = "";
        $subject_full = "";
        $sort_issuer = openssl_x509_parse($retc_value)['issuer'];
        $sort_subject = openssl_x509_parse($retc_value)['subject'];
        asort($sort_subject);
        foreach ($sort_subject as $sub_key => $sub_value) {
          $subject_full = "/" . $sub_key . "=" . $sub_value . $subject_full;
        }
        asort($sort_issuer);
        foreach ($sort_issuer as $iss_key => $iss_value) {
          $issuer_full = "/" . $iss_key . "=" . $iss_value . $issuer_full;
        }
        $crt_cn['cn'] = $subject_full;
        $crt_cn['issuer'] = $issuer_full;
        array_push($result["validation"]["cns"], $crt_cn);
      }
      $result["validation"]["correct_chain"] = $return_chain;
    }
    // hostname ip port
    $result["ip"] = $ip;
    if (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )) {
      $addr = inet_pton(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip));
      $unpack = unpack('H*hex', $addr);
      $hex = $unpack['hex'];
      $arpa = implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
      if (!empty(dns_get_record($arpa, DNS_PTR)[0]["target"])) {
        $result["hostname"] = dns_get_record($arpa, DNS_PTR)[0]["target"];
      } else {
        $result["hostname"] = "$host (No PTR available).";
      }
    } elseif (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
      if (!empty(gethostbyaddr(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip)))) {
        $result["hostname"] = gethostbyaddr(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip));
      } else {
        $result["hostname"] = "$host (No PTR available).";
      }
    } else {
      $result["hostname"] = "$host (No PTR available).";
    }
    $result["port"] = $port;

    if($fastcheck == 0) {
      //heartbleed
      $result['heartbleed'] = test_heartbleed($ip, $port);
      if ($result['heartbleed'] == "vulnerable") {
        $result["warning"][] = 'Vulnerable to the Heartbleed bug. Please update your OpenSSL ASAP!';
      }

      // compression
      $compression = conn_compression($host, $ip, $port);
      if ($compression == false) { 
        $result["compression"] = false;
      } else {
        // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
        // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        //   // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
        //   $result["warning"][] = 'SSL compression not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
        // } else {
          $result["compression"] = true;
          $result["warning"][] = 'SSL compression enabled. Please disable to prevent attacks like CRIME.';
        // }
        
      }

      // protocols
      $result["protocols"] = array_reverse(ssl_conn_protocols($host, $ip, $port));
      foreach ($result["protocols"] as $key => $value) {
        if ( $value == true ) {
          if ( $key == "sslv2") {
            $result["warning"][] = 'SSLv2 supported. Please disable ASAP and upgrade to a newer protocol like TLSv1.2.';
          }
          if ( $key == "sslv3") {
            $result["warning"][] = 'SSLv3 supported. Please disable and upgrade to a newer protocol like TLSv1.2.';
          }
        } else {
          if ( $key == "tlsv1.2") {
            $result["warning"][] = 'TLSv1.2 unsupported. Please enable TLSv1.2.';
          }
        }
      }

      // ciphersuites
        $ciphersuites_to_test = array('ECDHE-RSA-AES256-GCM-SHA384',
          'ECDHE-ECDSA-AES256-GCM-SHA384',
          'ECDHE-RSA-AES256-SHA384',
          'ECDHE-ECDSA-AES256-SHA384',
          'ECDHE-RSA-AES256-SHA',
          'ECDHE-ECDSA-AES256-SHA',
          'SRP-DSS-AES-256-CBC-SHA',
          'SRP-RSA-AES-256-CBC-SHA',
          'SRP-AES-256-CBC-SHA',
          'DH-DSS-AES256-GCM-SHA384',
          'DHE-DSS-AES256-GCM-SHA384',
          'DH-RSA-AES256-GCM-SHA384',
          'DHE-RSA-AES256-GCM-SHA384',
          'DHE-RSA-AES256-SHA256',
          'DHE-DSS-AES256-SHA256',
          'DH-RSA-AES256-SHA256',
          'DH-DSS-AES256-SHA256',
          'DHE-RSA-AES256-SHA',
          'DHE-DSS-AES256-SHA',
          'DH-RSA-AES256-SHA',
          'DH-DSS-AES256-SHA',
          'DHE-RSA-CAMELLIA256-SHA',
          'DHE-DSS-CAMELLIA256-SHA',
          'DH-RSA-CAMELLIA256-SHA',
          'DH-DSS-CAMELLIA256-SHA',
          'ECDH-RSA-AES256-GCM-SHA384',
          'ECDH-ECDSA-AES256-GCM-SHA384',
          'ECDH-RSA-AES256-SHA384',
          'ECDH-ECDSA-AES256-SHA384',
          'ECDH-RSA-AES256-SHA',
          'ECDH-ECDSA-AES256-SHA',
          'AES256-GCM-SHA384',
          'AES256-SHA256',
          'AES256-SHA',
          'CAMELLIA256-SHA',
          'PSK-AES256-CBC-SHA',
          'ECDHE-RSA-AES128-GCM-SHA256',
          'ECDHE-ECDSA-AES128-GCM-SHA256',
          'ECDHE-RSA-AES128-SHA256',
          'ECDHE-ECDSA-AES128-SHA256',
          'ECDHE-RSA-AES128-SHA',
          'ECDHE-ECDSA-AES128-SHA',
          'SRP-DSS-AES-128-CBC-SHA',
          'SRP-RSA-AES-128-CBC-SHA',
          'SRP-AES-128-CBC-SHA',
          'DH-DSS-AES128-GCM-SHA256',
          'DHE-DSS-AES128-GCM-SHA256',
          'DH-RSA-AES128-GCM-SHA256',
          'DHE-RSA-AES128-GCM-SHA256',
          'DHE-RSA-AES128-SHA256',
          'DHE-DSS-AES128-SHA256',
          'DH-RSA-AES128-SHA256',
          'DH-DSS-AES128-SHA256',
          'DHE-RSA-AES128-SHA',
          'DHE-DSS-AES128-SHA',
          'DH-RSA-AES128-SHA',
          'DH-DSS-AES128-SHA',
          'DHE-RSA-SEED-SHA',
          'DHE-DSS-SEED-SHA',
          'DH-RSA-SEED-SHA',
          'DH-DSS-SEED-SHA',
          'DHE-RSA-CAMELLIA128-SHA',
          'DHE-DSS-CAMELLIA128-SHA',
          'DH-RSA-CAMELLIA128-SHA',
          'DH-DSS-CAMELLIA128-SHA',
          'ECDH-RSA-AES128-GCM-SHA256',
          'ECDH-ECDSA-AES128-GCM-SHA256',
          'ECDH-RSA-AES128-SHA256',
          'ECDH-ECDSA-AES128-SHA256',
          'ECDH-RSA-AES128-SHA',
          'ECDH-ECDSA-AES128-SHA',
          'AES128-GCM-SHA256',
          'AES128-SHA256',
          'AES128-SHA',
          'SEED-SHA',
          'CAMELLIA128-SHA',
          'IDEA-CBC-SHA',
          'PSK-AES128-CBC-SHA',
          'ECDHE-RSA-RC4-SHA',
          'ECDHE-ECDSA-RC4-SHA',
          'ECDH-RSA-RC4-SHA',
          'ECDH-ECDSA-RC4-SHA',
          'RC4-SHA',
          'RC4-MD5',
          'PSK-RC4-SHA',
          'ECDHE-RSA-DES-CBC3-SHA',
          'ECDHE-ECDSA-DES-CBC3-SHA',
          'SRP-DSS-3DES-EDE-CBC-SHA',
          'SRP-RSA-3DES-EDE-CBC-SHA',
          'SRP-3DES-EDE-CBC-SHA',
          'EDH-RSA-DES-CBC3-SHA',
          'EDH-DSS-DES-CBC3-SHA',
          'DH-RSA-DES-CBC3-SHA',
          'DH-DSS-DES-CBC3-SHA',
          'ECDH-RSA-DES-CBC3-SHA',
          'ECDH-ECDSA-DES-CBC3-SHA',
          'DES-CBC3-SHA',
          'PSK-3DES-EDE-CBC-SHA',
          'EDH-RSA-DES-CBC-SHA',
          'EDH-DSS-DES-CBC-SHA',
          'DH-RSA-DES-CBC-SHA',
          'DH-DSS-DES-CBC-SHA',
          'DES-CBC-SHA',
          'EXP-EDH-RSA-DES-CBC-SHA',
          'EXP-EDH-DSS-DES-CBC-SHA',
          'EXP-DH-RSA-DES-CBC-SHA',
          'EXP-DH-DSS-DES-CBC-SHA',
          'EXP-DES-CBC-SHA',
          'EXP-RC2-CBC-MD5',
          'EXP-RC4-MD5',
          'ECDHE-RSA-NULL-SHA',
          'ECDHE-ECDSA-NULL-SHA',
          'AECDH-NULL-SHA',
          'ECDH-RSA-NULL-SHA',
          'ECDH-ECDSA-NULL-SHA',
          'NULL-SHA256',
          'NULL-SHA',
          'NULL-MD5');
        $tested_ciphersuites = ssl_conn_ciphersuites($host, $ip, $port, $ciphersuites_to_test);
        $result["supported_ciphersuites"] = array();
        foreach ($tested_ciphersuites as $key => $value) {
          if ($value == true) {
            $result["supported_ciphersuites"][] = $key;
          }
        }
        
      // tls_fallback_scsv
      $fallback = tls_fallback_scsv($host, $ip, $port);
      if ($fallback['protocol_count'] == 1) {
        $result["tls_fallback_scsv"] = "Only 1 protocol enabled, fallback not possible, TLS_FALLBACK_SCSV not required.";
      } else {
        if ($fallback['tls_fallback_scsv_support'] == 1) {
          $result["tls_fallback_scsv"] = "supported";
        } else {
          // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
          //if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
            //$result["warning"][] = 'TLS_FALLBACK_SCSV not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
          //} else {
            $result["tls_fallback_scsv"] = "unsupported";
            $result["warning"][] = "TLS_FALLBACK_SCSV unsupported. Please upgrade OpenSSL to enable. This offers downgrade attack protection.";
          //}
        }
      }
      //hsts
      $headers = server_http_headers($host, $ip, $port);
      if ($headers["strict-transport-security"]) {
        if ( is_array($headers["strict-transport-security"])) {
        $result["strict_sransport-security"] = substr($headers["strict-transport-security"][0], 0, 50);
        } else {
          $result["strict_transport_security"] = substr($headers["strict-transport-security"], 0, 50);
        }
      } else {
        $result["strict_transport_security"] = 'not set';
        $result["warning"][] = "HTTP Strict Transport Security not set.";
      }
      //hpkp
      if ( $headers["public-key-pins"] ) {
        if ( is_array($headers["public-key-pins"])) {
          $result["public_key_pins"] = substr($headers["public-key-pins"][0], 0, 255);
        } else {
          $result["public_key_pins"] = substr($headers["public-key-pins"], 0, 255);
        }
      } else {
        $result["public_key_pins"] = 'not set';
      }
      if ( $headers["public-key-pins-report-only"] ) {
        if ( is_array($headers["public-key-pins-report-only"])) {
          $result["public_key_pins_report_only"] = substr($headers["public-key-pins-report-only"][0], 0, 255);
        } else {
          $result["public_key_pins_report_only"] = substr($headers["public-key-pins-report-only"], 0, 255);
        }
      } 
      // ocsp stapling
      $stapling = ocsp_stapling($host, $ip, $port);
      if($stapling["working"] == 1) {
        $result["ocsp_stapling"] = $stapling;
      } else {
        // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
        // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        //   // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
        //   $result["warning"][] = 'OCSP Stapling not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
        // } else {
          $result["ocsp_stapling"] = "not set";
          $result["warning"][] = "OCSP Stapling not enabled.";
        // }
      }
      
      $result["heartbeat"] = heartbeat_test($host, $port);
    }
    $result["openssl_version"] = shell_exec("openssl version");
    $result["datetime_rfc2822"] = shell_exec("date --rfc-2822");
  } 
  return $result;
}
function crl_verify($raw_cert_data, $verbose=true) {
  global $random_blurp, $timeout;
  $cert_data = openssl_x509_parse($raw_cert_data);
  $cert_serial_nm = strtoupper(bcdechex($cert_data['serialNumber']));   
  $crl_uris = [];
  $crl_uri = explode("\nFull Name:\n ", $cert_data['extensions']['crlDistributionPoints']);
  foreach ($crl_uri as $key => $uri) {
    if (!empty($uri) ) {
      $uri = explode("URI:", $uri);
      foreach ($uri as $key => $crluri) {
        if (!empty($crluri) ) {
          $crl_uris[] = preg_replace('/\s+/', '', $crluri);
        }
      }
    }
  }
  foreach ($crl_uris as $key => $uri) {
    if (!empty($uri)) {
      if (0 === strpos($uri, 'http')) {
        $fp = fopen ("/tmp/" . $random_blurp .  "." . $key . ".crl", 'w+');
        $ch = curl_init(($uri));
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        if(curl_exec($ch) === false) {
          echo '<pre>Curl error: ' . htmlspecialchars(curl_error($ch)) ."</pre>";
        }
        curl_close($ch);
        if(stat("/tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl")['size'] < 10 ) {
          unlink("/tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl");
          return false;
        } 
        $crl_text = shell_exec("timeout " . $timeout . " openssl crl -noout -text -inform der -in /tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl 2>&1");

        $crl_last_update = shell_exec("timeout " . $timeout . " openssl crl -noout -lastupdate -inform der -in /tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl");

        $crl_next_update = shell_exec("timeout " . $timeout . " openssl crl -noout -nextupdate -inform der -in /tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl");

        unlink("/tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl");

        if ( strpos($crl_text, "unable to load CRL") === 0 ) {
          if ( $verbose ) {
            $result = "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span> - <span class='text-danger'>CRL invalid. (" . $uri . ")</span><br><pre> " . htmlspecialchars($crl_text) . "</pre>";
            return $result;
          } else {
            $result = "<span class='text-danger glyphicon glyphicon-remove'></span>";
            return $result;
          }
        }

        $crl_info = explode("Revoked Certificates:", $crl_text)[0];

        $crl_certificates = explode("Revoked Certificates:", $crl_text)[1];

        $crl_certificates = explode("Serial Number:", $crl_certificates); 
        $revcert = array('bla' => "die bla");
        foreach ($crl_certificates as $key => $revoked_certificate) {
          if (!empty($revoked_certificate)) {
            $revcert[str_replace(" ", "", explode("\n", $revoked_certificate)[0])] = str_replace("        Revocation Date: ", "", explode("\n", $revoked_certificate)[1]);
          }
        }
        if( array_key_exists($cert_serial_nm, $revcert) ) {
          if ( $verbose ) {
            $result = "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span> - <span class='text-danger'>REVOKED on " . $revcert[$cert_serial_nm] . ". " . $uri . "</span><br><pre>        " . $crl_last_update . "        " . $crl_next_update . "</pre>";
          } else {
            $result = "<span class='text-danger glyphicon glyphicon-remove'></span>";
          }
        } else {
          if ( $verbose ) {
            $result = "<span class='text-success glyphicon glyphicon-ok-sign'></span> <span class='text-success'> - " . $uri . "</span><br><pre>        " . $crl_last_update . "        " . $crl_next_update . "</pre>";
          } else {
            $result = "<span class='text-success glyphicon glyphicon-ok'></span>";
          }
        }
        return $result;
      }
    }
  }
}


function crl_verify_json($raw_cert_data) {
  global $random_blurp, $timeout;
  $result = [];
  $cert_data = openssl_x509_parse($raw_cert_data);
  $cert_serial_nm = strtoupper(bcdechex($cert_data['serialNumber']));   
  $crl_uris = [];
  $crl_uri = explode("\nFull Name:\n ", $cert_data['extensions']['crlDistributionPoints']);
  foreach ($crl_uri as $key => $uri) {
    if (isset($uri) ) {
      $uri = explode("URI:", $uri);
      $uri = $uri[1];    
      if (isset($uri) ) {
        $crl_uris[] = preg_replace('/\s+/', '', $uri);
      }
    }
  } 
  foreach ($crl_uris as $key => $uri) {
    $crl_no = $key+1; 
    if (0 === strpos($uri, 'http')) {
      $result[$crl_no]["crl_uri"] = $uri;
      $fp = fopen ("/tmp/" . $random_blurp .  "." . $key . ".crl", 'w+');
      $ch = curl_init(($uri));
      curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
      curl_setopt($ch, CURLOPT_FILE, $fp);
      curl_setopt($ch, CURLOPT_FAILONERROR, true);
      curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
      if(curl_exec($ch) === false) {
        $result[$crl_no]["error"] = 'Curl error: ' . htmlspecialchars(curl_error($ch));
      }
      curl_close($ch);
      if(stat("/tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl")['size'] < 10 ) {
        $result[$crl_no]["error"] = "crl could not be retreived";
      } 
      $crl_text = shell_exec("timeout " . $timeout . " openssl crl -noout -text -inform der -in /tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl 2>&1");

      $crl_last_update = shell_exec("timeout " . $timeout . " openssl crl -noout -lastupdate -inform der -in /tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl");
      $crl_last_update = explode("=", $crl_last_update)[1];

      $crl_next_update = shell_exec("timeout " . $timeout . " openssl crl -noout -nextupdate -inform der -in /tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl");
      $crl_next_update = explode("=", $crl_next_update)[1];

      unlink("/tmp/" . $random_blurp .  "." . escapeshellcmd($key) . ".crl");

      if ( strpos($crl_text, "unable to load CRL") === 0 ) {
        $result[$crl_no]["status"] = "invalid";
      }

      $crl_info = explode("Revoked Certificates:", $crl_text)[0];
      $crl_certificates = explode("Revoked Certificates:", $crl_text)[1];
      $crl_certificates = explode("Serial Number:", $crl_certificates); 
      $revcert = array();
      foreach ($crl_certificates as $key => $revoked_certificate) {
        if (!empty($revoked_certificate)) {
          $revcert[str_replace(" ", "", explode("\n", $revoked_certificate)[0])] = str_replace("        Revocation Date: ", "", explode("\n", $revoked_certificate)[1]);
        }
      }
      if( array_key_exists($cert_serial_nm, $revcert) ) {
        $result[$crl_no]["status"] = "revoked";
        $result[$crl_no]["revoked_on"] = $revcert[$cert_serial_nm];
        $result[$crl_no]["crl_last_update"] = $crl_last_update;
        $result[$crl_no]["crl_next_update"] = $crl_next_update;
      } else {
        $result[$crl_no]["status"] = "ok";
        $result[$crl_no]["crl_last_update"] = $crl_last_update;
        $result[$crl_no]["crl_next_update"] = $crl_next_update;
      }
    }
  }
  return $result;
}
function check_json($host,$ip,$port,$fastcheck=0) {
  global $timeout;
  global $max_chain_length;
  global $ct_urls;
  $old_error_reporting = error_reporting();
  error_reporting(0);
  $data = [];
  $stream = stream_context_create (array("ssl" => 
    array("capture_peer_cert" => true,
    "capture_peer_cert_chain" => true,
    "verify_peer" => false,
    "peer_name" => $host,
    "verify_peer_name" => false,
    "allow_self_signed" => true,
    "capture_session_meta" => true,
    "sni_enabled" => true)));
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )) {
    $connect_ip = "[" . $ip . "]";
  } else {
    $connect_ip = $ip;
  }
  $read_stream = stream_socket_client("ssl://$connect_ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream);
  if ( $read_stream === false ) {
    $data["error"] = ["Failed to connect: " . htmlspecialchars($errstr)];
    return $data;
  } else {
    $context = stream_context_get_params($read_stream);
    $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];
    $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"]);
    $chain_data = $context["options"]["ssl"]["peer_certificate_chain"];
    $chain_length = count($chain_data);
    if (isset($chain_data) && $chain_length < $max_chain_length) {
      $chain_length = count($chain_data);
      $chain_arr_keys  = ($chain_data);
      foreach(array_keys($chain_arr_keys) as $key) {
        $curr = $chain_data[$key];
        $next = $chain_data[$key+1];
        $prev = $chain_data[$key-1];
        $chain_key = (string)$key+1;
        $include_chain = false;
        if ($key == 0) {
          $data["connection"] = ssl_conn_metadata_json($host, $ip, $port, $read_stream, $chain_data, $fastcheck);
          $data["chain"][$chain_key] = cert_parse_json($curr, $next, $host, true, $port, $include_chain);
        } else {
          $data["chain"][$chain_key] = cert_parse_json($curr, $next, null, false, $port, $include_chain);
        }
        // certificate transparency
        $data["certificate_transparency"] = [];
        if($fastcheck == 0) {
          foreach ($ct_urls as $ct_url) {
            $submitToCT = submitCertToCT($data["chain"], $ct_url);
            $ct_result = json_decode($submitToCT, TRUE);
            if ($ct_result === null
              && json_last_error() !== JSON_ERROR_NONE) {
              $result_ct = array('result' => $submitToCT);
              $data["certificate_transparency"][$ct_url] = $result_ct;
            } else {
             $data["certificate_transparency"][$ct_url] = $ct_result;
            }
          }
        }
      } 
    } else {
      $data["error"] = ["Chain too long."];
      return $data;
    }
  }
  error_reporting($old_error_reporting);
  return $data;
}

function bcdechex($dec) {
    $hex = '';
    do {    
        $last = bcmod($dec, 16);
        $hex = dechex($last).$hex;
        $dec = bcdiv(bcsub($dec, $last), 16);
    } while($dec>0);
        return $hex;
}

function ocsp_stapling($host, $ip, $port) {
  //used openssl cli to check if host has enabled oscp stapling.
  global $timeout;
  // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
  // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
  //       // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
  //   return false;
  // }
  $result = "";
  // escapeshellcmd adds \[\] to ipv6 address.
  // todo: look into escapeshellarg vs. escapeshellcmd
  if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $output = shell_exec('echo | timeout ' . $timeout . ' openssl s_client -servername "' . escapeshellcmd($host) . '" -connect \'' . $ip . ':' . escapeshellcmd($port) . '\' -tlsextdebug -status 2>&1 | sed -n "/OCSP response:/,/---/p"'); 
  } else {
    $output = shell_exec('echo | timeout ' . $timeout . ' openssl s_client -servername "' . escapeshellcmd($host) . '" -connect "' . escapeshellcmd($ip) . ':' . escapeshellcmd($port) . '" -tlsextdebug -status 2>&1 | sed -n "/OCSP response:/,/---/p"'); 
  }
 
  if (strpos($output, "no response sent") !== false) { 
    $result = array("working" => 0,
      "cert_status" => "No response sent");
  }
  if (strpos($output, "OCSP Response Data:") !== false) {
    $lines = array();
    $output = preg_replace("/[[:blank:]]+/"," ", $output);
    $stapling_status_lines = explode("\n", $output);
    $stapling_status_lines = array_map('trim', $stapling_status_lines);
    foreach($stapling_status_lines as $line) {
      if(endsWith($line, ":") == false) {
        list($k, $v) = explode(":", $line);
        $lines[trim($k)] = trim($v);
      }
    }
    $result = array("working" => 1,
      "cert_status" => $lines["Cert Status"],
      "this_update" => $lines["This Update"],
      "next_update" => $lines["Next Update"],
      "responder_id" => $lines["Responder Id"],
      "hash_algorithm" => $lines["Hash Algorithm"],
      "signature_algorithm" => $lines["Signature Algorithm"],
      "issuer_name_hash" => $lines["Issuer Name Hash"]);
  }
  return $result;
}

function ocsp_verify_json($raw_cert_data, $raw_next_cert_data, $ocsp_uri) {
  //uses openssl cli to validate cert status with ocsp
  global $random_blurp, $timeout;
  $result = array();
  $tmp_dir = '/tmp/'; 
  $root_ca = getcwd() . '/cacert.pem';
  $pem_issuer = "";
  $pem_client = "";
  openssl_x509_export($raw_cert_data, $pem_client);
  openssl_x509_export_to_file($raw_cert_data, $tmp_dir.$random_blurp.'.cert_client.pem'); 
  openssl_x509_export($raw_next_cert_data, $pem_issuer);
  openssl_x509_export_to_file($raw_next_cert_data, $tmp_dir.$random_blurp.'.cert_issuer.pem');
  $isser_loc = $tmp_dir.$random_blurp.'.cert_issuer.pem';

  // Some OCSP's want HTTP/1.1 but OpenSSL does not do that. Add Host header as workaround.
  $ocsp_host = parse_url($ocsp_uri, PHP_URL_HOST);

  $output = shell_exec('timeout ' . $timeout . ' | openssl ocsp -resp_text -no_nonce -CAfile '.$root_ca.' -issuer '.$isser_loc .' -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST='. escapeshellcmd($ocsp_host) . '" 2>&1');
  
  $filter_output = shell_exec('timeout ' . $timeout . ' | openssl ocsp -resp_text -no_nonce -CAfile '.$root_ca.' -issuer '.$isser_loc .' -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST='. escapeshellcmd($ocsp_host) . '" 2>&1 | grep -v -e "to get local issuer certificate" -e "signer certificate not found" -e "Response Verify" -e "'. $tmp_dir.$random_blurp.'.cert_client.pem" | grep -e "Cert Status:" -e "Revocation Time:" -e "Revocation Reason:" -e "This Update:" -e "Next Update:" -e "OCSP Response Status:"');

  $output = preg_replace("/[[:blank:]]+/"," ", $output);
  $ocsp_status_lines = explode("\n", $output);
  $ocsp_status_lines = array_map('trim', $ocsp_status_lines);
  foreach($ocsp_status_lines as $line) {
    if(endsWith($line, ":") == false) {
      list($k, $v) = explode(":", $line, 2);
      if (trim($k)) {
        $lines[trim($k)] = trim($v); 
      }
    }
  }  
  
  if ($lines[$tmp_dir . $random_blurp . ".cert_client.pem"] == "good") { 
    $result["status"] = "good";
  } else if ($lines[$tmp_dir . $random_blurp . ".cert_client.pem"] == "revoked") {
    $result["status"] = "revoked";
  } else {
    $result["error"] = $filter_output;
    $result["status"] = "unknown";
  }  

  if (isset($lines["This Update"])) {
    $result["this_update"] = $lines["This Update"];
  }
  if (isset($lines["Next Update"])) {
    $result["next_update"] = $lines["Next Update"];
  }
  if (isset($lines["Reason"])) {
    $result["reason"] = $lines["Reason"];
  }
  if (isset($lines["Revocation Time"])) {
    $result["revocation_time"] = $lines["Revocation Time"];
  }
  $result["ocsp_uri"] = $ocsp_uri;
  //remove temp files after use
  unlink($tmp_dir.$random_blurp.'.cert_client.pem');
  unlink($tmp_dir.$random_blurp.'.cert_issuer.pem');

  return $result;
}

function get_sans_from_csr($csr) {
  global $random_blurp;
  global $timeout;
  //openssl_csr_get_subject doesn't support SAN names.
  $filename = "/tmp/csr-" . $random_blurp . "-" . gen_uuid() . ".csr.pem";
  $write_csr = file_put_contents($filename, $csr);
  if($write_csr !== FALSE) {
    $openssl_csr_output = trim(shell_exec("timeout " . $timeout . " openssl req -noout -text -in " . $filename . " | grep -e 'DNS:' -e 'IP:'"));
  }
  unlink($filename);
  if($openssl_csr_output) {
    $sans = array();
    $csr_san_dns = explode("DNS:", $openssl_csr_output);
    $csr_san_ip = explode("IP:", $openssl_csr_output);
    if(count($csr_san_dns) > 1) {
      foreach ($csr_san_dns as $key => $value) {
        if($value) {
          $san = trim(str_replace(",", "", str_replace("DNS:", "", $value)));
          array_push($sans, $san);
        }
      }
    }
    if(count($csr_san_ip) > 1) {
      foreach ($csr_san_ip as $key => $value) {
        if($value) {
          $san = trim(str_replace(",", "", str_replace("IP:", "", $value)));
          array_push($sans, $san);
        }
      }
    } 
  }
  if(count($sans) >= 1) {
    return $sans;
  }
}

function csr_parse($data) {
  //parses the json data from csr_parse_json() to a nice html page.
  echo "<table class='table table-striped table-bordered'>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Certificate Signing Request Data</strong></td>";
  echo "</tr>";
  foreach ($data['subject'] as $key => $value) {
    echo "<tr><td>";
    switch ($key) {
      case 'C':
      echo "Country";
      break;
      case 'ST':
      echo "State";
      break;
      case 'L':
      echo "City";
      break;
      case 'O':
      echo "Organization";
      break;
      case 'OU':
      echo "Organizational Unit";
      break;
      case 'CN':
      echo "Common Name";
      break;
      case 'mail':
      echo "Email Address";
      break;
      default:
      echo htmlspecialchars($key);
      break;
    }
    echo "</td><td>";
    switch ($key) {
      case 'C':
      echo htmlspecialchars($value);
      echo ' <img src="'.htmlspecialchars($current_folder) . 'img/blank.gif" class="flag flag-';
      echo strtolower(htmlspecialchars($value)); 
      echo '" alt="" />';
      break;
      case 'DC':
      foreach ($value as $key => $value) {
        echo htmlspecialchars($value) . ".";
      }
      break;
      default:
      if (is_array($value)) {
        foreach ($value as $key => $value) {
          echo htmlspecialchars($value) . " ";
        }
      } else {
        echo htmlspecialchars($value);
      }
      break;
    }
    echo "</td></tr>\n";
  }

  if($data['csr_sans']) {
      echo "<tr><td>Subject Alternative Names</td><td><ul>";
      foreach ($data['csr_sans'] as $key => $value) {
        echo "<span style='font-family:monospace;'><li>";
        echo htmlspecialchars($value);
        echo "</li>";
      }
      echo "</ul></td></tr>";
  }

  echo "<tr><td>Public Key PEM (";
  echo htmlspecialchars($data['details']['bits']);
  if ($data['details']['rsa']) {
    echo " RSA";
  }
  if ($data['details']['dsa']) {
    echo " DSA";
  }
  if ($data['details']['dh']) {
    echo " DH";
  }
  if ($data['details']['ec']) {
    echo " ECDSA";
  }
  echo ")</td><td><pre>";
  echo htmlspecialchars($data['details']['key']);
  echo "</pre></td></tr>";

  echo "<tr><td>CSR PEM</td><td><pre>";
  echo htmlspecialchars($data['csr_pem']);
  echo "</pre></td></tr>";
  echo "</table>";
}


function cert_parse($data) {
  //parses the json data from cert_parse_json() to a nice html page.
  //does output formatting based on some parts, like red if cert expired.
  if (is_array($data["warning"]) && count($data["warning"]) >= 1) {
    $data["warning"] = array_unique($data["warning"]);
    if (count($data["warning"]) == 1) {
      echo "<h3>" . count($data["warning"]) . " warning!</h3>";
    } else {
      echo "<h3>" . count($data["warning"]) . " warnings!</h3>";
    }
    foreach ($data["warning"] as $key => $value) {
      echo "<div class='alert alert-danger' role='alert'>";
      echo htmlspecialchars($value);
      echo "</div>";
    }
  }
  echo "<table class='table table-striped table-bordered'>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Certificate Data</strong></td>";
  echo "</tr>";
  $today = date("Y-m-d");
  echo "<tr><td colspan='2'>\n";
  echo "<table class='table'>\n";
  echo "<thead><tr>\n";
  echo "<th>Hostname</th>\n";
  echo "<th>Not Expired</th>\n";
  echo "<th>Issuer</th>\n";
  echo "<th>CRL</th>\n";
  echo "<th>OCSP</th>\n";
  echo "<th>Signing Type</th>\n";
  echo "</tr>\n</thead>\n<tbody>\n<tr>";
  // hostname validation
  if ($data["hostname_in_san_or_cn"] == "true") {
    echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
  } elseif ($data["hostname_in_san_or_cn"] == "false")  {
    echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
  } elseif ($data["hostname_in_san_or_cn"] == "n/a; ca signing certificate")  {
    echo "<td></td>";
  } else {
    echo "<td><h1><span class='text-danger glyphicon glyphicon-question-sign'></span>&nbsp;</h1></td>";
  }
  // expired
  if ( $today > date(DATE_RFC2822,$data['cert_data']['validFrom_time_t']) || strtotime($today) < strtotime(date(DATE_RFC2822,$data['cert_data']['validTo_time_t'])) ) {
    echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
  } else {
    echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
  }
  // issuer
  if (!empty($data["issuer_valid"])) {
    if ($data["issuer_valid"] == true) {
      echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
    } else {
      echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
    }
  } else {
    echo '<td> </td>';
  }
  // crl
  if ( !empty($data['crl'][1]['status']) ) {
    if ($data['crl'][1]['status'] == "ok") {
      echo "<td><h1><span class='text-success glyphicon glyphicon-ok'></span>&nbsp;</h1></td>";
    } else {
      echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
    }
  } else {
    echo '<td> </td>';
  }
  // ocsp
  if (!empty($data['ocsp'][1]['ocsp_uri'])) {
    echo "<td>";
    if ($data['ocsp'][1]["status"] == "good") { 
      echo '<h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1>';
    } else if ($data['ocsp'][1]["status"] == "revoked") {
      echo '<h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1>';
    } else {
      echo '<h1><span class="text-danger glyphicon glyphicon-question-sign"></span>&nbsp;</h1>';
    }
    echo "</td>";
  } else {
    echo "<td> </td>";
  }
  // self signed/ca/ca root
  if (strpos($data['cert_data']['extensions']['basicConstraints'], "CA:TRUE") !== false && $data['cert_data']['issuer']['CN'] == $data['cert_data']['subject']['CN'] ) {
    echo '<td><span class="text-success">CA Root Certificate</span></td>';
  } else if (strpos($data['cert_data']['extensions']['basicConstraints'], "CA:TRUE") !== false) {
    echo '<td><span class="text-success">CA Certificate</span></td>';
  } else if ($data['cert_data']['issuer']['CN'] == $data['cert_data']['subject']['CN']) {
    echo '<td><span class="text-danger">Self Signed</span></td>';
  } else {
    echo "<td>Signed by CA</td>";
  }
  echo "</tr>";
  echo "</tbody></table>";
  echo "</td></tr>";
  if (!empty($data['cert_data']['subject']) ) {
    foreach ($data['cert_data']['subject'] as $key => $value) {
      echo "<tr><td>";
      switch ($key) {
        case 'C':
        echo "Country";
        break;
        case 'ST':
        echo "State";
        break;
        case 'L':
        echo "City";
        break;
        case 'O':
        echo "Organization";
        break;
        case 'OU':
        echo "Organizational Unit";
        break;
        case 'CN':
        echo "Common Name";
        break;
        case 'mail':
        echo "Email Address";
        break;
        case 'businessCategory':
        echo "Business Type";
        break;
        default:
        echo htmlspecialchars($key);
        break;
      }
      echo "</td><td>";
      switch ($key) {
        case 'C':
        echo htmlspecialchars($value);
        echo ' <img src="'.htmlspecialchars($current_folder) . 'img/blank.gif" class="flag flag-';
        echo strtolower(htmlspecialchars($value)); 
        echo '" alt="" />';
        break;
        case 'DC':
        foreach ($value as $key => $value) {
          echo htmlspecialchars($value) . ".";
        }
        break;
        default:
        if (is_array($value)) {
          foreach ($value as $key => $value) {
            echo htmlspecialchars($value) . " ";
          }
        } else {
          echo htmlspecialchars($value);
        }
        break;
      }
      echo "</td>";
      echo "</tr>";
    }
  }
  // san
  if (!empty($data['cert_data']['extensions']['subjectAltName'])) {
  echo "<tr>";
  echo "<td>Subject Alternative Names</td>";
  echo "<td>";
  foreach ( explode("DNS:", $data['cert_data']['extensions']['subjectAltName']) as $altName ) {
    if ( !empty(str_replace(',', " ", "$altName"))) {
      echo "<span style='font-family:monospace;'>";
      echo htmlspecialchars(str_replace(',', " ", "$altName"));
      echo "</span><br>";
    }
  } 
  echo "</td>";
  echo "</tr>";
  }
  // validation type
  echo "<tr>";
  echo "<td>Type</td>";
  echo "<td>";
  if ($data["validation_type"] == "extended") {
    echo '<span class="text-success">Extended Validation</span>';
  } elseif ($data["validation_type"] == "organization") {
    echo "Organization Validation";
  } elseif ($data["validation_type"] == "domain") {
    echo "Domain Validation";
  }
  // full subject
  echo "</td>";
  echo "</tr>";
  echo "<tr>";
  echo "<td>Full Subject</td>";
  echo "<td><span style='font-family:monospace;'>";
  echo htmlspecialchars($data['cert_data']['name']);
  echo "</span></td>";
  echo "</tr>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Issuer</strong></td>";
  echo "</tr>";
  if (!empty($data['cert_data']['issuer']) ) {
    foreach ($data['cert_data']['issuer'] as $key => $value) {
      echo "<tr><td>";
      switch ($key) {
        case 'C':
        echo "Country";
        break;
        case 'ST':
        echo "State";
        break;
        case 'L':
        echo "City";
        break;
        case 'O':
        echo "Organization";
        break;
        case 'OU':
        echo "Organizational Unit";
        break;
        case 'CN':
        echo "Common Name";
        break;
        case 'mail':
        echo "Email Address";
        break;
        case 'emailAddress':
        echo "Email Address";
        break;
        default:
        echo htmlspecialchars($key);
        break;
      }
      echo "</td><td>";
      switch ($key) {
        case 'C':
        echo htmlspecialchars($value);
        echo ' <img src="'.htmlspecialchars($current_folder) . 'img/blank.gif" class="flag flag-';
        echo strtolower(htmlspecialchars($value)); 
        echo '" alt="" />';
        break;
        case 'DC':
        foreach ($value as $key => $value) {
          echo htmlspecialchars($value) . ".";
        }
        break;
        default:
        if (is_array($value)) {
          foreach ($value as $key => $value) {
            echo htmlspecialchars($value) . " ";
          }
        } else {
          echo htmlspecialchars($value);
        }
        break;
      }
      echo "</td>";
      echo "</tr>";
    }
  }
  // valid from 
  echo "<tr>";
  echo "<td colspan='2'><strong>Validity</strong></td>";
  echo "</tr>";
  if ( !empty($data['cert_data']['validFrom_time_t']) ) { 
    echo "<tr>";
    echo "<td>Valid From</td>";
    echo "<td>";
    if ( $today < date(DATE_RFC2822,$data['cert_data']['validFrom_time_t']) ) {
      echo '<span class="text-success glyphicon glyphicon-ok-sign"></span>';
      echo '<span class="text-success"> - ';
    } else {
      echo '<span class="text-danger glyphicon glyphicon-exclamation-sign"></span>';
      echo '<span class="text-danger"> - ';
    }
    echo htmlspecialchars(date(DATE_RFC2822,$data['cert_data']['validFrom_time_t'])); 
    echo "</span>";
    echo "</td>";
    echo "</tr>";
  }
  // issued to expired
  if ( !empty($data['cert_data']['validTo_time_t']) ) { 
    echo "<tr>";
    echo "<td>Valid Until</td>";
    echo "<td>";
    if ( strtotime($today) < strtotime(date(DATE_RFC2822,$data['cert_data']['validTo_time_t'])) ) {
      echo '<span class="text-success glyphicon glyphicon-ok-sign"></span>';
      echo '<span class="text-success"> - ';
    } else {
      echo '<span class="text-danger glyphicon glyphicon-exclamation-sign"></span>';
      echo '<span class="text-danger"> - ';
    }
    echo htmlspecialchars(date(DATE_RFC2822,$data['cert_data']['validTo_time_t'])); 
    echo "</span>";
    echo "</td>";
    echo "</tr>";
  };
  if ( is_array($data['crl']) ) {
    echo "<tr>";
    echo "<td>CRL</td>";
    echo "<td>";
    foreach ($data['crl'] as $key => $value) {
      if ($value) {
        if ($value["status"] == "ok") {
          echo "<span class='text-success glyphicon glyphicon-ok-sign'></span>";
          echo "<span class='text-success'> - Not on CRL: " . htmlspecialchars($value["crl_uri"]) . "</span><br>";
          echo "Last update: " . htmlspecialchars($value['crl_last_update']) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value['crl_next_update']) . "<br>\n";
        } elseif ($value["status"] == "revoked") {
          echo "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span>";
          echo "<span class='text-danger'> - Revoked on CRL: " . htmlspecialchars($value["crl_uri"]) . "</span><br>\n";
          echo "<span class='text-danger'>Revocation date: " . htmlspecialchars($value["revoked_on"]) . "</span><br>\n";
          echo "<br>Last update: " . htmlspecialchars($value['crl_last_update']) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value['crl_next_update']) . "<br>\n";
        } else {
          echo "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span>";
          echo "<span class='text-danger'> - CRL invalid: (" . htmlspecialchars($value["crl_uri"]) . ")</span><br>";
          echo "<pre> " . htmlspecialchars($value["error"]) . "</pre>";
        }
      }
      if (count($data['ocsp']) > 1) {
        echo "<hr>";
      }
    }
    echo "</td>";
    echo "</tr>";
  } else {
    echo "<tr><td>CRL</td><td>No CRL URI found in certificate</td></tr>";
  }
  // ocsp
  if ( is_array($data['ocsp'])) { 
    echo "<tr>";
    echo "<td>OCSP</td>";
    echo "<td>";
    foreach ($data['ocsp'] as $key => $value) {
      if ($value) {
        if ($value["status"] == "good") { 
          echo '<span class="text-success glyphicon glyphicon-ok-sign"></span> ';
          echo '<span class="text-success"> - OK: ';
          echo htmlspecialchars($value['ocsp_uri']);
          echo "</span><br>";
          echo "Last update: " . htmlspecialchars($value["this_update"]) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value["next_update"]) . "<br>\n";
        } else if ( $value["status"] == "revoked") {
          echo '<span class="text-danger glyphicon glyphicon-remove-sign"></span>';
          echo '<span class="text-danger"> - REVOKED: ';
          echo htmlspecialchars($value['ocsp_uri']);
          echo "</span><br>";
          echo "<span class='text-danger'>Revocation Time: " . htmlspecialchars($value["revocation_time"]) . "<br>\n";
          echo "Revocation Reason: " . htmlspecialchars($value["reason"]). "</span><br>";
          echo "<br>Last update: " . htmlspecialchars($value["this_update"]) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value["next_update"]) . "<br>\n";
        } else {
          echo '<span class="text-danger glyphicon glyphicon-question-sign"></span>';
          echo '<span class="text-danger"> - UNKNOWN: ';
          echo " - " . htmlspecialchars($value['ocsp_uri']) . "</span><br>";
          echo "<pre>" . htmlspecialchars($value["error"]) . "</pre>";
        }
      }
      if (count($data['ocsp']) > 1) {
        echo "<hr>";
      }
    }
  } else {
    if ($data["ocsp"] == "No issuer cert provided. Unable to send OCSP request.") {
      echo "<tr><td>OCSP</td><td>No issuer certificate provided. Unable to send OCSP request.</td></tr>";
    } else {
      echo "<tr><td>OCSP</td><td>No OCSP URI found in certificate</td></tr>";
    }
  }
  if(!empty($_GET['host'])) {
    echo "<tr>";
    echo "<td>Hostname Validation</td>";
    echo "<td>";
    // hostname validation
    if ($data["hostname_in_san_or_cn"] == "true") {
      echo "<span class='text-success glyphicon glyphicon-ok'></span>\n<span class='text-success'> - ";
      echo htmlspecialchars($data['hostname_checked']);
      echo " found in CN or SAN.</span>";
    } elseif ($data["hostname_in_san_or_cn"] == "false")  {
      echo '<span class="text-danger glyphicon glyphicon-remove"></span><span class="text-danger"> - ';
      echo htmlspecialchars($data['hostname_checked']); 
      echo ' NOT found in CN or SAN.</span>';
    } elseif ($data["hostname_in_san_or_cn"] == "n/a; ca signing certificate")  {
      echo "Not applicable, this seems to be a CA signing certificate.";
    } else {
      echo "Not applicable, this seems to be a CA signing certificate.";
    }
    echo "</td>";
    echo "</tr>";
  }
  // details
  echo "<tr>";
  echo "<td colspan='2'><strong>Details</strong></td>";
  echo "</tr>";
  if ( !empty($data['cert_data']['purposes']) ) { 
    echo "<tr>";
    echo "<td>Purposes</td>";
    echo "<td>";
    foreach ($data['cert_data']['purposes'] as $key => $purpose) {
      if ($purpose["general"]) {
        echo htmlspecialchars($key);
        echo " ";
      }
    }
    echo "</td>";
    echo "</tr>";
    echo "<tr>";
    echo "<td>Purposes CA</td>";
    echo "<td>";
    foreach ($data['cert_data']['purposes'] as $key => $purpose) {
      if ($purpose["ca"]) {
        echo htmlspecialchars($key);
        echo " ";
      }
    }
    echo "</td>";
    echo "</tr>";
  }
  // serial number
  if (!empty($data['serialNumber']) ) { 
    echo "<tr>";
    echo "<td>Serial</td>";
    echo "<td>";
    echo "<span style='font-family:monospace;'>" . htmlspecialchars($data['serialNumber']) . "</span>";
    echo "</td>";
    echo "</tr>";
  }
  echo "<tr>";
  echo "<td>Key Size / Type</td>";
  echo "<td>";
  // key details
  echo htmlspecialchars($data["key"]['bits']);
  echo " bits ";
  echo htmlspecialchars($data["key"]['type']);
  echo "</td>";
  echo "</tr>";
  echo "<tr>";
  echo "<td>";
  echo "Weak debian key";
  echo "</td>";
  if ($data["key"]["weak_debian_rsa_key"] == 1) {
    echo "<td>";
    echo "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span><span class='text-danger'> - This is a <a href='https://wiki.debian.org/SSLkeys'>weak debian key</a>. Replace it as soon as possible.</span>";
    echo "</td>";
  } else {
    echo "<td>";
    echo "This is not a <a href='https://wiki.debian.org/SSLkeys'>weak debian key</a>.";
    echo "</td>";
  }
  echo "</tr>";
  echo "<tr>";
  echo "<td>Signature Algorithm</td>";
  echo "<td>";
  echo $data["key"]["signature_algorithm"];
  echo "</td>";
  echo "</tr>";

  echo "<tr>";
  echo "<td>Hashes</td>";
  echo "<td>";
    echo "<table class='table table-striped'>";
    foreach ($data["hash"] as $key => $value) {
      echo "<tr><td>";
      echo htmlspecialchars(strtoupper($key));
      echo "</td><td><span style='font-family:monospace;'>";
      echo wordwrap(htmlspecialchars($value), 64, "<br>\n", TRUE);
      echo "</span></td></tr>";
    }
  echo "</table>";
  echo "</td>";
  echo "</tr>";

  if ($_GET['fastcheck'] == 0 && !empty($_GET['host'])) {
    echo "<tr>";
    echo "<td>TLSA DNS </td>";
    echo "<td>";
    if($data['tlsa']['error'] == 'none' && !empty($data['tlsa'])) {
      echo "<table class='table table-striped'>";
      foreach ($data["tlsa"] as $key => $value) {
        switch ($key) {
          case 'tlsa_hash':
            echo "<tr><td>Record Data</td><td>" . htmlspecialchars($value) . "</td></tr>";
            break;
          case 'tlsa_usage':
            echo "<tr><td>Usage</td><td>";
            switch ($value) {
              case '0':
                echo "0: PKIX-TA: Certificate Authority Constraint";
                break;
              case '1':
                echo "1: PKIX-EE: Service Certificate Constraint";
                break;
              case '2':
                echo "2: DANE-TA: Trust Anchor Assertion";
                break;
              case '3':
                echo "3: DANE-EE: Domain Issued Certificate";
                break;
              default:
                echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Incorrect usage parameter: ". htmlspecialchars($value) . "</span>";
                break;
            }
            break;
          case 'tlsa_selector':
            echo "<tr><td>Selector</td><td>";
            switch ($value) {
              case '0':
                echo "0: Cert: Use full certificate";
                break;
              case '1':
                echo "1: SPKI: Use subject public key";
                break;
              default:
                echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Incorrect selector parameter: ". htmlspecialchars($value) . "</span>";
                break;
            }
            break;
          case 'tlsa_matching_type':
            echo "<tr><td>Matching Type</td><td>";
            switch ($value) {
              case '0':
                echo "0: Full: No Hash";
                break;
              case '1':
                echo "1: SHA-256 hash";
                break;
              case '2':
                echo "2: SHA-512 hash";
                break;
              default:
                echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Incorrect matching type parameter: ". htmlspecialchars($value) . "</span>";
                break;
            }
            break;      
          }
      echo "</td></tr>";
      }
      if ($data['tlsa']['tlsa_matching_type'] == "1" || $data['tlsa']['tlsa_matching_type'] == 2) {
        echo "<tr><td>DNS Hash Matches Certificate Hash</td><td>";
        if($data['tlsa']['tlsa_matching_type'] == '1') {
          echo "SHA 256 ";
          if ($data['tlsa']['tlsa_hash'] == $data['hash']['sha256']) {
            echo "<span class='text-success glyphicon glyphicon-ok'></span><span class='text-success'> - Hash match</span>";
          } else {
            echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Hash does not match</span>";
          }
        }
        if($data['tlsa']['tlsa_matching_type'] == '2') {
          echo "SHA 512 ";
          if ($data['tlsa']['tlsa_hash'] == $data['hash']['sha512']) {
            echo "<span class='text-success glyphicon glyphicon-ok'></span><span class='text-success'> Hash match</span>";
          } else {
            echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Hash does not match</span>";
          }
        }
      }
      echo "</table>";
    } else {
      echo "<p>";
      echo htmlspecialchars($data['tlsa']['error']);
      if($data['tlsa']['example']) {
        echo "Here's an example TLSA record based on this certificate's SHA-256 hash: <br><pre>";
        echo htmlspecialchars($data['tlsa']['example']);
        echo "</pre></p>";
      }
    }
    echo "<p>Please note that the DNSSEC chain is not validated. The status of the DNSSEC signature will not show up here.<br><a href='https://wiki.mozilla.org/Security/DNSSEC-TLS-details'>More information about TLSA and DNSSEC.</a> - Simple TLSA record generator <a href='https://www.huque.com/bin/gen_tlsa'>here</a>.";
    echo "</td>";
    echo "</tr>";
  }
  
  if (count($data['cert_data']['extensions']) >= 1) {
    echo "<tr>";
    echo "<td>Extensions</td>";
    echo "<td>";
    ?>
    <div class="panel-group" id="accordion<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" aria-expanded="false" aria-controls="collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <div class="panel-body">
            <?php 
            foreach ($data['cert_data']['extensions'] as $name=>$extension) {

              if ( !empty(str_replace(',', " ", "$extension"))) {
                echo "<strong>" . htmlspecialchars("$name") . "</strong>";
                echo "<pre>";
                echo htmlspecialchars($extension);
                echo "</pre>";
              }
            } 
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";
  } else {
    echo "<tr>";
    echo "<td>Extensions</td>";
    echo "<td>";
    echo "None";
    echo "</td>";
    echo "</tr>";
  }
  if(!empty($data["key"]["certificate_pem"])) {
    echo "<tr>";
    echo "<td>Certificate PEM </td>";
    echo "<td>";
    ?>
    <div class="panel-group" id="pem-accordion<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" aria-expanded="false" aria-controls="pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <div class="panel-body">
            <?php 
            echo "<pre>";
            echo htmlspecialchars($data["key"]["certificate_pem"]);
    echo "</pre>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";
  }
            
  if(!empty($data['key']['public_key_pem'])) {
    echo "<tr>";
    echo "<td>Public Key PEM </td>";
    echo "<td>";
    ?>
    <div class="panel-group" id="pub-pem-accordion<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="pub-pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#pub-pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" aria-expanded="false" aria-controls="pub-pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="pub-pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="pub-pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <div class="panel-body">
            <?php
              echo "<pre>"; 
              echo htmlspecialchars($data['key']['public_key_pem']);
    echo "</pre>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";

  // correct chain
  if (is_array($data["correct_chain"]["chain"])) {
    echo "<tr>";
    echo "<td>Certificate Chain</td>";
    echo "<td>";
    echo "<p>We've constructed the certificate chain in the correct order of this certificate based on the '<code>authorityInfoAccess</code>' extension and earlier saved certificates. The result also contains this certificate as the first one.<br>";

    echo "<p>This is our best guess at the correct CA Chain: <br><ul>";
    foreach ($data['correct_chain']['cns'] as $cn_key => $cn_value) {
      foreach ($cn_value as $cnn_key => $cnn_value) {
        echo "<span style='font-family: monospace;'><li>";
        if($cnn_key == 'cn') {
          echo "Name.......: ";
          echo htmlspecialchars($cnn_value);
          echo "</li></span>  ";
        }
        if ($cnn_key == 'issuer') {
          echo "Issued by..: ";
          echo htmlspecialchars($cnn_value);
          echo "</li></span><br>";
        }
      }
    }
    echo "</ul></p>";
    echo "<p>Click below to see the full chain output in PEM format, copy-pastable in most software.</p>";
    ?>
    <div class="panel-group" id="accordion-correct-chain" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="heading-correct-chain">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#collapse-correct-chain" aria-expanded="false" aria-controls="collapse-correct-chain">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="collapse-correct-chain" class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading-correct-chain">
          <div class="panel-body">
    <?php
    echo "<pre>"; 
    foreach ($data['correct_chain']['chain'] as $cert) {
      echo htmlspecialchars($cert);
      echo "<br>";
    }
    echo "</pre>"; 
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";
  }


    echo "<tr>";
    echo "<td><a href='https://raymii.org/s/articles/HTTP_Public_Key_Pinning_Extension_HPKP.html'>SPKI Hash</a></td>";
    echo "<td>";
    print("<span style='font-family:monospace;'>" . htmlspecialchars($data['key']['spki_hash']) . "</span>");
    echo "</td>";
    echo "</tr>";
  }
  echo "</tbody>";
  echo "</table>";
}
    



































function cert_parse_json($raw_cert_data, $raw_next_cert_data=null, $host=null, $validate_hostname=false, $port="443", $include_chain=null) {
  global $random_blurp;
  global $ev_oids;
  global $timeout;
  $result = array();
  $cert_data = openssl_x509_parse($raw_cert_data);
  if (isset($raw_next_cert_data)) {
    $next_cert_data = openssl_x509_parse($raw_next_cert_data);
  }
  $today = date("Y-m-d"); 
  //cert 
  if (isset($cert_data) ) {
    // purposes
    $purposes = array();
    foreach ($cert_data['purposes'] as $key => $purpose) {
      $purposes[$purpose[2]]["ca"] = $purpose[1];
      $purposes[$purpose[2]]["general"] = $purpose[0];
    }
    unset($cert_data['purposes']);
    $cert_data['purposes'] = $purposes;
    $result["cert_data"] = $cert_data;
  }

// valid from 
  if ( !empty($result['cert_data']['validFrom_time_t']) ) { 
    if ( $today < date(DATE_RFC2822,$result['cert_data']['validFrom_time_t']) ) {
      $result['cert_issued_in_future'] = false;
    } else {
      $result['cert_issued_in_future'] = true;
      $result['warning'][] = "Certificate issue date is in the future: " . date(DATE_RFC2822,$data['cert_data']['validFrom_time_t']); 
    }
  }
  // expired
  if (!empty($cert_data['validTo_time_t'])) { 
    if ($today > date(DATE_RFC2822,$cert_data['validFrom_time_t']) || strtotime($today) < strtotime(date(DATE_RFC2822,$cert_data['validTo_time_t']))) {
      $result['cert_expired'] = false;
    } else {
      $result['cert_expired'] = true;
      $result['warning'][] = "Certificate expired! Expiration date: " . date(DATE_RFC2822,$cert_data['validTo_time_t']);
    }
  }
  // almost expired
  if (!empty($cert_data['validTo_time_t'])) {
    $certExpiryDate = strtotime(date(DATE_RFC2822,$cert_data['validTo_time_t']));
    $certExpiryDiff = $certExpiryDate - strtotime($today);
    if ($certExpiryDiff < 2592000) {
      $result['cert_expires_in_less_than_thirty_days'] = true;
      $result['warning'][] = "Certificate expires in " . round($certExpiryDiff / 84600) . " days!. Expiration date: " . date(DATE_RFC2822,$certExpiryDate);
    } else {
      $result['cert_expires_in_less_than_thirty_days'] = false;
    }
  }

  if ( array_search(explode("Policy: ", explode("\n", $cert_data['extensions']['certificatePolicies'])[0])[1], $ev_oids) ) {
    $result["validation_type"] = "extended";
  } else if ( isset($cert_data['subject']['O'] ) ) {
    $result["validation_type"] = "organization";
  } else if ( isset($cert_data['subject']['CN'] ) ) {
    $result["validation_type"] = "domain";
  }
  // issuer
  if ($raw_next_cert_data) {
    if (verify_cert_issuer_by_subject_hash($raw_cert_data, $raw_next_cert_data) ) {
      $result["issuer_valid"] = true; 
    } else {
      $result["issuer_valid"] = false;
      $result['warning'][] = "Provided certificate issuer does not match issuer in certificate. Sent chain order wrong.";
    }
  } 
  // crl
  if (isset($cert_data['extensions']['crlDistributionPoints']) ) {
    $result["crl"] = crl_verify_json($raw_cert_data);
    if (is_array($result["crl"])) {
      foreach ($result["crl"] as $key => $value) {
        if ($value["status"] == "revoked") {
          $result['warning'][] = "Certificate revoked on CRL: " . $value['crl_uri'] . ". Revocation time: " . $value['revoked_on'] . ".";
        }
      }
    }
  } else {
    $result["crl"] = "No CRL URI found in certificate";
  }
  // ocsp
  if (isset($cert_data['extensions']['authorityInfoAccess'])) { 
    $ocsp_uris = explode("OCSP - URI:", $cert_data['extensions']['authorityInfoAccess']);
    unset($ocsp_uris[0]);
    if (isset($ocsp_uris) ) {
      if (isset($raw_next_cert_data)) {
        foreach ($ocsp_uris as $key => $ocsp_uri) {
          $ocsp_uri = explode("\n", $ocsp_uri)[0];
          $ocsp_uri = explode(" ", $ocsp_uri)[0];
          $result["ocsp"]["$key"] = ocsp_verify_json($raw_cert_data, $raw_next_cert_data, $ocsp_uri);
          if ($result['ocsp'][$key]["status"] == "revoked") {
            $result['warning'][] = "Certificate revoked on OCSP: " . $result['ocsp'][$key]['ocsp_uri'] . ". Revocation time: " . $result['ocsp'][$key]['revocation_time'] . ".";
          } elseif ($result['ocsp'][$key]["status"] == "unknown") {
            $result['warning'][] = "OCSP error on: " . $result['ocsp'][$key]['ocsp_uri'] . ".";
          }
        } 
      } else {
        $result["ocsp"] = "No issuer cert provided. Unable to send OCSP request.";
      }
    } else {
        $result["ocsp"] = "No OCSP URI found in certificate";
    }
  } else {
    $result["ocsp"] = "No OCSP URI found in certificate";
  }
  // hostname validation
  if ($validate_hostname == true) {
    $result["hostname_checked"] = $host;
    if (isset($cert_data['subject']['CN'])) {
      if ( verify_certificate_hostname($raw_cert_data, $host) ) {
        $result["hostname_in_san_or_cn"] = "true";
      } else {
        $result["hostname_in_san_or_cn"] = "false";
        $result['warning'][] = "Hostname " . $host . " not found in certificate.";
      }
    }
  } else {
    $result["hostname_in_san_or_cn"] = "n/a; ca signing certificate";
  }
  //serial number
  if ( isset($cert_data['serialNumber']) ) { 
    $serial = [];
    $sn = str_split(strtoupper(bcdechex($cert_data['serialNumber'])), 2);
    $sn_len = count($sn);
    foreach ($sn as $key => $s) {
      $serial[] = htmlspecialchars($s);
      if ( $key != $sn_len - 1) {
        $serial[] = ":";
      }
    }
    $result["serialNumber"] = implode("", $serial);
  }

  // key details
  $key_details = openssl_pkey_get_details(openssl_pkey_get_public($raw_cert_data));
  $export_pem = "";
  openssl_x509_export($raw_cert_data, $export_pem);

  // save pem. this because the reconstruct chain function works better
  // this way. not all certs have authorityinfoaccess. We first check if
  // we already have a matching cert.
  if (!is_dir('crt_hash')) {
    mkdir('crt_hash');
  }
  // filenames of saved certs are hashes of the asort full subject. 
  $sort_subject = $cert_data['subject'];
  asort($sort_subject);
  foreach ($sort_subject as $key => $value) {
    $name_full = "/" . $key . "=" . $value . $name_full;
  }
  $crt_hash = hash("sha256", $name_full);
  $crt_hash_folder = "crt_hash/";
  $crt_hash_file = $crt_hash_folder . $crt_hash . ".pem";
  if(file_exists($crt_hash_file)) {
    if (time()-filemtime($crt_hash_file) > 5 * 84600) {
      // file older than 5 days. crt might have changed, retry.
      $content_hash = sha1_file($crt_hash_file);
      rename($crt_hash_file, $crt_hash_folder . $content_hash . "content_hash_save.pem");
      file_put_contents($crt_hash_file, $export_pem);
    }
  } else {
    file_put_contents($crt_hash_file, $export_pem);
  }
  if(stat($crt_hash_file)['size'] < 10 ) {
    //probably a corrupt file. sould be at least +100KB.
    unlink($crt_hash_file);
  }

  //chain reconstruction
  if($include_chain && $raw_cert_data) {
    $return_chain = array();
    $export_pem = "";
    openssl_x509_export($raw_cert_data, $export_pem);
    $crt_cn = openssl_x509_parse($raw_cert_data)['name'];
    $export_pem = "#start " . $crt_cn . "\n" . $export_pem . "\n#end " . $crt_cn . "\n";
    array_push($return_chain, $export_pem);
    $certificate_chain = array();
    $issuer_crt = get_issuer_chain($raw_cert_data);
    if (count($issuer_crt['certs']) >= 1) {
      $issuercrts = array_unique($issuer_crt['certs']);
      foreach ($issuercrts as $key => $value) {
        array_push($return_chain, $value);
      }
    }
    $return_chain = array_unique($return_chain);
    if(count($return_chain) > 1) {
      $result["correct_chain"]["cns"] = array();
      $crt_cn = array();
      foreach ($return_chain as $retc_key => $retc_value) {
        $issuer_full = "";
        $subject_full = "";
        $sort_issuer = openssl_x509_parse($retc_value)['issuer'];
        $sort_subject = openssl_x509_parse($retc_value)['subject'];
        asort($sort_subject);
        foreach ($sort_subject as $sub_key => $sub_value) {
          $subject_full = "/" . $sub_key . "=" . $sub_value . $subject_full;
        }
        asort($sort_issuer);
        foreach ($sort_issuer as $iss_key => $iss_value) {
          $issuer_full = "/" . $iss_key . "=" . $iss_value . $issuer_full;
        }
        $crt_cn['cn'] = $subject_full;
        $crt_cn['issuer'] = $issuer_full;
        array_push($result["correct_chain"]["cns"], $crt_cn);
      }
      $result["correct_chain"]["chain"] = $return_chain;
    }
  }

  //hashes
  $string = $export_pem;
  $pattern = '/-----(.*)-----/';
  $replacement = '';
  $string = preg_replace($pattern, $replacement, $string);

  $pattern = '/\n/';
  $replacement = '';
  $export_pem_preg = preg_replace($pattern, $replacement, $string);
  $export_pem_preg = wordwrap($export_pem_preg, 77, "\n", TRUE);
  $result['hash']['md5'] = cert_hash('md5',       $export_pem_preg);
  $result['hash']['sha1'] = cert_hash('sha1',     $export_pem_preg);
  $result['hash']['sha256'] = cert_hash('sha256', $export_pem_preg);
  $result['hash']['sha384'] = cert_hash('sha384', $export_pem_preg);
  $result['hash']['sha512'] = cert_hash('sha512', $export_pem_preg);
  
  //TLSA check
  if (!empty($cert_data['subject']['CN']) && !empty($host)) {
    if ($validate_hostname == true) {
      $tlsa_record = shell_exec("timeout " . $timeout . " dig +short +dnssec +time=" . $timeout . " TLSA _" . escapeshellcmd($port) . "._tcp." . escapeshellcmd($host) . " 2>&1 | head -n 1");
      if (!empty($tlsa_record)) {
        $tlsa = explode(" ", $tlsa_record, 4);
        $pattern = '/ /';
        $replacement = '';
        $result['tlsa']['tlsa_hash'] = trim(strtolower(preg_replace($pattern, $replacement, $tlsa[3])));
        $result['tlsa']['tlsa_usage'] = $tlsa[0];
        $result['tlsa']['tlsa_selector'] = $tlsa[1];
        $result['tlsa']['tlsa_matching_type'] = $tlsa[2];
        $result['tlsa']['error'] = 'none';
      } else {

        $result['tlsa']['error'] = 'No TLSA record found.';
        $result['tlsa']['example'] = '_'. htmlspecialchars($port) . '._tcp.' . htmlspecialchars($host) . ' IN TLSA 3 0 1 ' . $result['hash']['sha256'] . ';';
      }
    } else {
      $result['tlsa']['error'] = 'CA certificate, TLSA not applicable.';
    }
  }
  if (isset($key_details['rsa'])) {
    $result["key"]["type"] = "rsa";
    $result["key"]["bits"] = $key_details['bits'];
    if ($key_details['bits'] < 2048) {
      $result['warning'][] = $key_details['bits'] . " bit RSA key is not safe. Upgrade to at least 4096 bits.";
    }
  
  // weak debian key check
  $bin_modulus = $key_details['rsa']['n'];
  # blacklist format requires sha1sum of output from "openssl x509 -noout -modulus" including the Modulus= and newline.
  # create the blacklist:
  # https://packages.debian.org/source/squeeze/openssl-blacklist
  # svn co svn://svn.debian.org/pkg-openssl/openssl-blacklist/
  # find openssl-blacklist/trunk/blacklists/ -iname "*.db" -exec cat {} >> unsorted_blacklist.db \;
  # sort -u unsorted_blacklist.db > debian_blacklist.db

  $mod_sha1sum = sha1("Modulus=" . strtoupper(bin2hex($bin_modulus)) . "\n");
  $blacklist_file = fopen('inc/debian_blacklist.db', 'r');
  $key_in_blacklist = false;
  while (($buffer = fgets($blacklist_file)) !== false) {
      if (strpos($buffer, $mod_sha1sum) !== false) {
          $key_in_blacklist = true;
          break; 
      }      
    }
    fclose($blacklist_file);
    if ($key_in_blacklist == true) {
      $result["key"]["weak_debian_rsa_key"] = "true";
      $result['warning'][] = "Weak debian key found. Remove this key right now and create a new one.";
    }
  } else if (isset($key_details['dsa'])) {
  $result["key"]["type"] = "dsa";
    $result["key"]["bits"] = $key_details['bits'];
  } else if (isset($key_details['dh'])) {
    $result["key"]["type"] = "dh";
    $result["key"]["bits"] = $key_details['bits'];
  } else if (isset($key_details['ec'])) {
    $result["key"]["type"] = "ecdsa";
    $result["key"]["bits"] = $key_details['bits'];
  } else {
    $result["key"]["type"] = "unknown";
    $result["key"]["bits"] = $key_details['bits'];
  }
  // signature algorithm
  $result["key"]["signature_algorithm"] = cert_signature_algorithm($raw_cert_data);
  if ($result["key"]["signature_algorithm"] == "sha1WithRSAEncryption") {
    $result['warning'][] = "SHA-1 certificate. Upgrade (re-issue) to SHA-256 or better.";
  }
  if(isset($export_pem)) {
    $result["key"]["certificate_pem"] = $export_pem;
  }
  if(isset($key_details['key'])) {
    $result["key"]["public_key_pem"] = $key_details['key'];
    $result["key"]["spki_hash"] = spki_hash($export_pem);
  }
  return $result;
}











function csr_parse_json($csr) {
  //if csr or cert is pasted in form tis function parses the csr or it send the cert to cert_parse.
  global $random_blurp;
  global $timeout;
  $result = array();
  if (strpos($csr, "BEGIN CERTIFICATE REQUEST") !== false) { 
    $cert_data = openssl_csr_get_public_key($csr);
    $cert_details = openssl_pkey_get_details($cert_data);
    $cert_key = $cert_details['key'];
    $cert_subject = openssl_csr_get_subject($csr);
    $result["subject"] = $cert_subject;
    $result["key"] = $cert_key;
    $result["details"] = $cert_details; 
    if ($cert_details) {
      $result["csr_pem"] = $csr;
      $sans = get_sans_from_csr($csr);
      if(count($sans) > 1) {
        $result["csr_sans"] = $sans;
      }
    }
  } elseif (strpos($csr, "BEGIN CERTIFICATE") !== false) { 
    $result = cert_parse_json($csr, null, null, null, null, true);
  } else {
    $result = array("error" => "data not valid csr");
  }
  return $result;
}


function pre_dump($var) {
  //this function is amazing whilst debugging.
  echo "<pre>";
  var_dump($var);
  echo "</pre>";
}

function utf8encodeNestedArray($arr) {
  // json_encode fails with binary data. utf-8 encode that first, some ca's like to encode images in their OID's (verisign, 1.3.6.1.5.5.7.1.12)...
  $encoded_arr = array();
  foreach ($arr as $key => $value) {
    if (is_array($value)) {
      $encoded_arr[utf8_encode($key)] = utf8encodeNestedArray($value);
    } else {
      $encoded_arr[utf8_encode($key)] = utf8_encode($value); 
    }
  }
  return $encoded_arr;
}

//two helper functions to check if string starts or end with, from stack overflow.
function startsWith($haystack, $needle) {
  // search backwards starting from haystack length characters from the end
  return $needle === "" || strrpos($haystack, $needle, -strlen($haystack)) !== FALSE;
}
function endsWith($haystack, $needle) {
  // search forward starting from end minus needle length characters
  if(!empty($haystack)) {
    return $needle === "" || strpos($haystack, $needle, strlen($haystack) - strlen($needle)) !== FALSE;
  }
}

function get_current_folder(){
  //not current OS folder, but current web folder.
  //used for relative links and css/js files
  $url = $_SERVER['REQUEST_URI']; 
  $parts = explode('/',$url);
  $folder = '';
  for ($i = 0; $i < count($parts) - 1; $i++) {
    $folder .= $parts[$i] . "/";
  }
  return $folder;
}

$current_folder = get_current_folder();

function gen_uuid() {
  //from stack overflow.
  return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
    // 32 bits for "time_low"
    mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),

    // 16 bits for "time_mid"
    mt_rand( 0, 0xffff ),

    // 16 bits for "time_hi_and_version",
    // four most significant bits holds version number 4
    mt_rand( 0, 0x0fff ) | 0x4000,

    // 16 bits, 8 bits for "clk_seq_hi_res",
    // 8 bits for "clk_seq_low",
    // two most significant bits holds zero and one for variant DCE1.1
    mt_rand( 0, 0x3fff ) | 0x8000,

    // 48 bits for "node"
    mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
  );
}


function tls_fallback_scsv($host, $ip, $port) {
    global $timeout;
    // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
    // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    //     // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
    //     return false;
    // }
    $result = [];
    $protocols = ssl_conn_protocols($host, $ip, $port);
    if (count(array_filter($protocols)) > 1) {
        $result['protocol_count'] = count(array_filter($protocols));
        // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
        if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $fallback_test = shell_exec("echo | timeout $timeout openssl s_client -servername \"" . escapeshellcmd($host) . "\" -connect '" . $ip . ":" . escapeshellcmd($port) . "' -fallback_scsv -no_tls1_2 2>&1 >/dev/null");
        } else {
            $fallback_test = shell_exec("echo | timeout $timeout openssl s_client -servername \"" . escapeshellcmd($host) . "\" -connect " . escapeshellcmd($ip) . ":" . escapeshellcmd($port) . " -fallback_scsv -no_tls1_2 2>&1 >/dev/null");
        }
        if ( stripos($fallback_test, "SSL alert number 86") !== false ) {
            $result['tls_fallback_scsv_support'] = 1;
        }
    } else {
        $result['protocol_count'] = 1;
    }
    return $result;
}


$timeout = 120;

# max chain length (big chain slows down checks)
$max_chain_length = 10;

# Don't change stuff down here.
date_default_timezone_set('UTC');

$version = 3.2;

ini_set('default_socket_timeout', $timeout);

//used for random filenames in /tmp in crl and ocsp checks
$random_blurp = rand(10,99999);

// 2015-09-21 http://www.certificate-transparency.org/known-logs
// $ct_urls = ["https://ct.ws.symantec.com", 
//         "https://ct.googleapis.com/pilot",
//         "https://ct.googleapis.com/aviator", 
//         "https://ct.googleapis.com/rocketeer",
//         "https://ct1.digicert-ct.com/log",
//         "https://ct.izenpe.com",
//         "https://ctlog.api.venafi.com", 
//         "https://log.certly.io"];
$ct_urls = ["https://ct.googleapis.com/aviator"];


# 2014-11-10 (nov) from wikipedia
$ev_oids = array("1.3.6.1.4.1.34697.2.1", "1.3.6.1.4.1.34697.2.2", "1.3.6.1.4.1.34697.2.3", "1.3.6.1.4.1.34697.2.4", "1.2.40.0.17.1.22", "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.17326.10.14.2.1.2", "1.3.6.1.4.1.17326.10.8.12.1.2", "1.3.6.1.4.1.6449.1.2.1.5.1", "2.16.840.1.114412.2.1", "2.16.840.1.114412.1.3.0.2", "2.16.528.1.1001.1.1.1.12.6.1.1.1", "2.16.840.1.114028.10.1.2", "0.4.0.2042.1.4", "0.4.0.2042.1.5", "1.3.6.1.4.1.13177.10.1.3.10", "1.3.6.1.4.1.14370.1.6", "1.3.6.1.4.1.4146.1.1", "2.16.840.1.114413.1.7.23.3", "1.3.6.1.4.1.14777.6.1.1", "2.16.792.1.2.1.1.5.7.1.9", "1.3.6.1.4.1.22234.2.5.2.3.1", "1.3.6.1.4.1.782.1.2.1.8.1", "1.3.6.1.4.1.8024.0.2.100.1.2", "1.2.392.200091.100.721.1", "2.16.840.1.114414.1.7.23.3", "1.3.6.1.4.1.23223.2", "1.3.6.1.4.1.23223.1.1.1", "2.16.756.1.83.21.0", "2.16.756.1.89.1.2.1.1", "2.16.840.1.113733.1.7.48.1", "2.16.840.1.114404.1.1.2.4.1", "2.16.840.1.113733.1.7.23.6", "1.3.6.1.4.1.6334.1.100.1", "2.16.840.1.114171.500.9", "1.3.6.1.4.1.36305.2");


function parse_hostname($u_hostname){
    # parses the URL and if no extea IP given, returns all A/AAAA records for that IP.
    # format raymii.org:1.2.34.56 should do SNI request to that ip.
    # parts[0]=host, parts[1]=ip
    $port = 0;
    $hostname = 0;
    $parts = explode(":", $u_hostname, 2);
    
    if (idn_to_ascii($parts[0])) {
        $parts[0] = idn_to_ascii($parts[0]);
    }
    $parts[0] = preg_replace('/\\s+/', '', $parts[0]);
    $parts[0] = preg_replace('/[^A-Za-z0-9\.\:-]/', '', $parts[0]);
    $hostname = mb_strtolower($parts[0]);
    
    if (count($parts) > 1) {
        $parts[1] = preg_replace('/\\s+/', '', $parts[1]);
        $parts[1] = preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $parts[1]);
        if (filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) or filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
            $ip = mb_strtolower($parts[1]);
        } 
    } else {
        if (filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
            $ip = $hostname;
        } else {    
            $dns_a_records = dns_get_record($hostname, DNS_A);
            $dns_aaaa_records = dns_get_record($hostname, DNS_AAAA);
            $dns_records = array_merge($dns_a_records, $dns_aaaa_records);
            if (count($dns_a_records) > 1 or count($dns_aaaa_records) > 1 or (count($dns_a_records) + count($dns_aaaa_records) > 1)) {
                $result = array('hostname' => $hostname, 'ip' => $ip, 'multiple_ip' => $dns_records);
                return $result;
            } else {
                $ip = fixed_gethostbyname($hostname);
            }
        }
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $ip = "[" . $ip . "]";
    }

    $result = array('hostname' => $hostname, 'ip' => $ip);
    return $result;
}

function choose_endpoint($ips, $host, $port, $fastcheck) {
    //if we detect multiple A/AAAA records, then show a page to choose the endpoint
    global $version;
    echo "<div id='page-content-wrapper'>\n";
    echo "<div class='container-fluid'>\n";
    echo "<div class='row'>\n";
    // if ajax-ed, don't show header again
    if(empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
      echo "<div class='col-md-10 col-md-offset-1'>\n";
      echo "<div class='page-header'>\n";
      echo "<h1><a style='color:black;' href=\"";
      echo(htmlspecialchars($current_folder));
      echo "\">SSL Decoder</a></h1>\n";
      echo "</div>\n";
    }
    //this div is hidden and only shown when an endpoint is choosen.
    echo "<div id='preloader'>\n";
    echo "<p>\n";
    echo "<img src=\"";
    echo(htmlspecialchars($current_folder));
    echo 'img/ajax-loader.gif" />';
    echo "<br>&nbsp;<br>\n";
    echo "The SSL Decoder is processing your request. Please wait a few moments.<br>\n";
    echo "</p>\n";
    echo "</div>\n";
    echo "<div id='resultDiv'></div>\n";
    echo "<div class='content' id='choose_endp'>\n<section id='choose_endpoint'>\n";
    echo "<header>\n<h2>Multiple endpoints for " . htmlspecialchars($host) . "</h2>\n</header>\n";
    echo "<p>We've found multiple A or AAAA records for " . htmlspecialchars($host) . ". Please choose the host you want to scan from the list below:</p>\n<br>\n";
    echo "<ul>\n";
    foreach ($ips as $ip) {
        echo "<li>";
        echo "<a onclick=\"showdiv('preloader'); hidediv('choose_endp');\" href=\"";
        echo htmlspecialchars($current_folder);
        echo "?host=";
        echo htmlspecialchars($host);
        echo ":";
        //ipv6 url's require [1234::5678] format
        if ($ip['type'] == 'A') {
            echo htmlspecialchars($ip['ip']);
        } elseif ($ip['type'] == 'AAAA') {
            echo "[";
            echo htmlspecialchars($ip['ipv6']);
            echo "]";
        }
        echo "&port=";
        echo htmlspecialchars($port);
        echo "&fastcheck=";
        if ($fastcheck == 1) {
            echo 1;
        } else {
            echo 0;
        }
        echo "\">";
        if ($ip['type'] == 'A') {
            echo htmlspecialchars($ip['ip']);
        } elseif ($ip['type'] == 'AAAA') {
            echo "[";
            echo htmlspecialchars($ip['ipv6']);
            echo "]";
        }
        echo " (port: ";
        echo htmlspecialchars($port);
        echo ")</a>";
        echo "</li>";
    }

    echo "</ul>\n";
    echo "</section></div>\n";
    echo "</div>\n";
    echo "</div>\n";
    echo "</div>\n";

    require_once("inc/footer.php");
    exit;
}


function cert_hash($hash_alg, $raw_cert_to_hash) {
  //returns the hash of the a certificate. Same as "openssl alg" cli.
  $cert_hash = hash($hash_alg, base64_decode($raw_cert_to_hash));
  return $cert_hash; 
}

function verify_certificate_hostname($raw_cert, $host) {
  //validates hostname to check with hostnames in certificate CN or subjectAltNames
  $cert_data = openssl_x509_parse($raw_cert);
  if ($cert_data['subject']['CN']) {
    $cert_host_names = [];
    $cert_host_names[] = $cert_data['subject']['CN'];
    if ($cert_data['extensions']['subjectAltName']) {
      foreach ( explode("DNS:", $cert_data['extensions']['subjectAltName']) as $altName ) {
        foreach (explode(",", $altName) as $key => $value) {
          if ( !empty(str_replace(',', "", "$value"))) {
            $cert_host_names[] = str_replace(" ", "", str_replace(',', "", "$value"));
          }
        }
      }
    }
    foreach ($cert_host_names as $key => $hostname) {
      if (strpos($hostname, "*.") === 0) {
        // wildcard hostname from cert
        if (explode(".", $host, 2)[1] == explode(".", $hostname, 2)[1] ) {
        // split cert name and host name on . and compare everything after the first dot
          return true;
        }
      }
      // no wildcard, just regular match
      if ($host == $hostname) {
        return true;
      }
    }
    // no match
    return false;
  }
}



function verify_cert_issuer_by_subject_hash($raw_cert_data, $raw_next_cert_data) {
  //checks if the issuer of given cert is the same as the subject of the other cert, thus validating if cert 1 was signed by cert 2.
  global $random_blurp;
  global $timeout;
  $tmp_dir = "/tmp/";
  openssl_x509_export_to_file($raw_next_cert_data, $tmp_dir.$random_blurp.'.cert_issuer.pem');
  openssl_x509_export_to_file($raw_cert_data, $tmp_dir.$random_blurp.'.cert_client.pem'); 

  $cert_issuer_hash = shell_exec('timeout ' . $timeout . ' openssl x509 -noout -issuer_hash -in '.$tmp_dir.$random_blurp.'.cert_client.pem 2>&1');
  $issuer_subject_hash = shell_exec('timeout ' . $timeout . ' openssl x509 -noout -subject_hash -in '.$tmp_dir.$random_blurp.'.cert_issuer.pem 2>&1');

  //remove those temp files.
  unlink($tmp_dir.$random_blurp.'.cert_client.pem');
  unlink($tmp_dir.$random_blurp.'.cert_issuer.pem');
  if ( $cert_issuer_hash == $issuer_subject_hash ) {
    return true;
  } else {
    return false;
  }
}

function cert_signature_algorithm($raw_cert_data) {
  $cert_read = openssl_x509_read($raw_cert_data);
  //if param 3 is FALSE, $out is filled with both the PEM file as wel all the contents of `openssl x509 -noout -text -in cert.pem.
  //we use that to get the signature alg.
  openssl_x509_export($cert_read, $out, FALSE);
  $signature_algorithm = null;
  if(preg_match('/^\s+Signature Algorithm:\s*(.*)\s*$/m', $out, $match)) {
    $signature_algorithm = $match[1];
  }
  return($signature_algorithm);
}

function spki_hash($raw_cert_data) {
  global $timeout;
  global $random_blurp;
  $tmp_dir = '/tmp/'; 
  //below command returns the SPKI hash of a public key.
  openssl_x509_export_to_file($raw_cert_data, $tmp_dir.$random_blurp.'.cert_client.pem'); 
  $output = shell_exec('timeout ' . $timeout . ' openssl x509 -noout -in '.$tmp_dir.$random_blurp.'.cert_client.pem  -pubkey | openssl asn1parse -noout -inform pem -out '.$tmp_dir.$random_blurp.'.public.key; openssl dgst -sha256 -binary '. $tmp_dir . $random_blurp . '.public.key | openssl enc -base64 2>&1');
  //remove those files again.
  unlink($tmp_dir.$random_blurp.'.cert_client.pem');
  unlink($tmp_dir.$random_blurp.'.public.key');
  return(trim(htmlspecialchars($output)));
}



$write_cache = 0;
$epoch = date('U');
$random_bla = md5(uniqid(rand(), true));
// foreach (glob("functions/*.php") as $filename) {
//   include $filename;
// }

print_r($_GET);
if ( isset($_GET['host']) && !empty($_GET['host'])) {
  $data = [];
  $hostname = mb_strtolower(get($_GET['host']));
  $hostname = parse_hostname($hostname);
  if ($hostname['multiple_ip']) {
    $data["error"] = ["Host format is incorrect. (use \$host:\$ip.)"];
  } 
  $host = $hostname['hostname'];
  $ip = $hostname['ip'];
  $port = get($_GET['port'], '443');
  if ( !is_numeric($port) ) {
    $port = 443;
  }
  $fastcheck = $_GET['fastcheck'];
  $write_cache = 1;
  $hostfilename = preg_replace("([^\w\s\d\-_~,;:\[\]\(\).])", '', $host);
  $hostfilename = preg_replace("([\.]{2,})", '', $host);
  $hostfilename = preg_replace("([^a-z0-9])", '', $host);
  $cache_filename = (string) "results/saved." . $hostfilename . "." . $epoch . "." . $random_bla . ".api.json";
  $data["data"] = check_json($host, $ip, $port, $fastcheck);
} elseif(isset($_GET['csr']) && !empty($_GET['csr'])) {
  $write_cache = 1;
  $cache_filename = (string) "results/saved.csr." . $epoch . "." . $random_bla . ".api.json";
  $data["data"]["chain"]["1"] = csr_parse_json($_GET['csr']);
} else {
  $data["error"] = ["Host is required"];
}

$data['version'] = $version;
$data = utf8encodeNestedArray($data);

if(isset($data["data"]["error"])) {
  $data["error"] = $data["data"]["error"];
  unset($data["data"]);
}

if ($_GET["type"] == "pretty") {
  header('Content-Type: text/html');
  echo "<pre>";
  echo htmlspecialchars(json_encode($data,JSON_PRETTY_PRINT));
  echo "</pre>";
  ?>
  <!-- Piwik -->
  <script type="text/javascript">
    var _paq = _paq || [];
    _paq.push(['trackPageView']);
    _paq.push(['enableLinkTracking']);
    (function() {
      var u="//hosted-oswa.org/piwik/";
      _paq.push(['setTrackerUrl', u+'piwik.php']);
      _paq.push(['setSiteId', 34]);
      var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
      g.type='text/javascript'; g.async=true; g.defer=true; g.src=u+'piwik.js'; s.parentNode.insertBefore(g,s);
    })();
  </script>
  <noscript><p><img src="//hosted-oswa.org/piwik/piwik.php?idsite=34" style="border:0;" alt="" /></p></noscript>
  <!-- End Piwik Code -->
  <?php
} else {
  header('Content-Type: application/json');
  echo json_encode($data);
}


if ($write_cache == 1) {
  if (!file_exists($cache_filename)) {
    file_put_contents($cache_filename, json_encode($data));
  }
}

?>

