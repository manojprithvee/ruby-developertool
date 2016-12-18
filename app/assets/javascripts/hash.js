$(document).ready(function () {
$('#text').on("input",function () {
    $("#output").html("<div id='wrapper' class='jumbotron'><div class='profile-main-loader'><div class='loader'><svg class='circular-loader'viewBox='25 25 50 50' ><circle class='loader-path' cx='50' cy='50' r='20' fill='none' stroke='#70c542' stroke-width='2' /></svg></div></div></div></div>");
    $.ajax({url: "https://developertoolsphp.herokuapp.com/hash.php?string="+$(this).val(), success: function(result){
        $("#output").html(result)
        
    }
}).fail(function() {
    $("#output").html("<div class='jumbotron'><strong>There is a Problem</strong></div>");
  });
});
});