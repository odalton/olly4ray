(function ($, Drupal, window, document, undefined) {


// To understand behaviors, see https://drupal.org/node/756722#behaviors
  Drupal.behaviors.isotope = {
    attach: function(context, settings) {

      $('.view-our-story').isotope({
        itemSelector : '.views-row',
        layoutMode: "masonry",

      });


//      $('.view-our-story').isotope({
//        itemSelector : '.views-row',
//        layoutMode : 'fitRows',
//
//        resizable: false,
//        animationEngine: 'best-available'
//
//      });
//
//
//      var $container = $('.view-our-story'),
//        $body = $('body'),
//        colW = 60,
//        columns = null;
//
//      $container.isotope({
//        // disable window resizing
//        resizable: false,
//        masonry: {
//          columnWidth: colW
//        }
//      });
//
//      $(window).smartresize(function(){
//        // check if columns has changed
//        var currentColumns = Math.floor( ( $body.width() -10 ) / colW );
//
//        if ( currentColumns !== columns ) {
//          // set new column count
//          columns = currentColumns;
//          // apply width to container manually, then trigger relayout
//          $container.width( columns * colW )
//            .isotope('reLayout');
//        }
//
//      }).smartresize(); // trigger resize to set container width


    }
  };


})(jQuery, Drupal, this, this.document);
