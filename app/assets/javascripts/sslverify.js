$(document).ready(function () {
$("#Submit").on("click",function(){
    if ($("#Submit").html()=="Submit"){
    
    urls=$("#url").val()
    if (urls!=""){
        $("#Submit").html("Loading...")
        $("#output").html("<p>Process has started it might take upto  5 minutes for it to be done..")
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