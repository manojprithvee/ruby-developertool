$(document).ready(function () {
$("#Submit").on("click",function(){
    if ($("#Submit").html()=="Submit"){
    
    urls=$("#url").val()
    if (urls!=""){
        $("#Submit").html("Loading...")
        $("#output").html("<div id='wrapper' class='jumbotron'><div class='profile-main-loader'><div class='loader'><svg class='circular-loader'viewBox='25 25 50 50' ><circle class='loader-path' cx='50' cy='50' r='20' fill='none' stroke='#70c542' stroke-width='2' /></svg></div></div></div></div>");
        $.ajax({url: "/api/sslverify?host="+urls, success: function(result){
            console.log(result)
            $("#output").html(result)
        }
        }).done(function() {
            $("#Submit").html("Submit")
        });
        
    }
    else{
        $("#output").html("ERROR:Input Empty..")
    }
    }
    
});
});