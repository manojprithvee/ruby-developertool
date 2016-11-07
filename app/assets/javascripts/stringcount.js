Array.prototype.remove = function(elem, all) {
  for (var i=this.length-1; i>=0; i--) {
    if (this[i] === elem) {
        this.splice(i, 1);
        if(!all)
          break;
    }
  }
  return this;
};

       $(document).ready(function () {
           teststring=$('#inputDatabaseName')
        $(".length").html(0);
        $(".wordlenght").html(0);
        $(".uniqlenght").html(0);
        $(".uniqwordlenght").html(0);
        $("#ignorecase").on("click",function(){
            console.log($(this).is(':checked'))
            if (!teststring.val().length==0){
            if ($(this).is(':checked')== false){
            $(".length").html(teststring.val().length );
            $(".wordlenght").html(teststring.val().split(" ").length );
            $(".uniqlenght").html(jQuery.unique(teststring.val().split("")).length );
            $(".uniqwordlenght").html(jQuery.unique(teststring.val().split(" ").remove("",true)).length );
            }
            

            else{
            $(".length").html(teststring.val().toLowerCase().length );
            $(".wordlenght").html(teststring.val().toLowerCase().split(" ").length );
            $(".uniqlenght").html(jQuery.unique(teststring.val().toLowerCase().split("")).length );
            $(".uniqwordlenght").html(jQuery.unique(teststring.val().toLowerCase().split(" ").remove("",true)).length );
            }
            }
            else{
               $(".length").html(0);
                $(".wordlenght").html(0);
                $(".uniqlenght").html(0);
                $(".uniqwordlenght").html(0);
            }
            
        });
        $('#inputDatabaseName').on("input",function () {
            if (!teststring.val().length==0){
            if ($("#ignorecase").is(':checked')== false){
            $(".length").html(teststring.val().length );
            $(".wordlenght").html(teststring.val().split(" ").remove("",true).length );
            $(".uniqlenght").html(jQuery.unique(teststring.val().split("")).length );
            $(".uniqwordlenght").html(jQuery.unique(teststring.val().split(" ").remove("",true)).length );
            }
            else{
            $(".length").html(teststring.val().toLowerCase().length );
            $(".wordlenght").html(teststring.val().toLowerCase().split(" ").length );
            $(".uniqlenght").html(jQuery.unique(teststring.val().toLowerCase().split("")).length );
            $(".uniqwordlenght").html(jQuery.unique(teststring.val().toLowerCase().split(" ").remove("",true)).length );
            }
            }
            else{
                $(".length").html(0);
                $(".wordlenght").html(0);
                $(".uniqlenght").html(0);
                $(".uniqwordlenght").html(0);
            }
        });
         });