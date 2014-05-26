/**
 * @file
 * A JavaScript file for the theme.
 *
 * In order for this JavaScript to be loaded on pages, see the instructions in
 * the README.txt next to this file.
 */

// JavaScript should be made compatible with libraries other than jQuery by
// wrapping it with an "anonymous closure". See:
// - https://drupal.org/node/1446420
// - http://www.adequatelygood.com/2010/3/JavaScript-Module-Pattern-In-Depth
(function ($, Drupal, window, document, undefined) {


// To understand behaviors, see https://drupal.org/node/756722#behaviors
Drupal.behaviors.my_custom_behavior = {
  attach: function(context, settings) {

    // Place your code here.
    new gnMenu( document.getElementById( 'gn-menu' ) );


    $(document).ready(function() {

      $("body.section-setting .view-content").owlCarousel({
        autoPlay: 5000,
        navigation : false, // Show next and prev buttons
        slideSpeed : 300,
        paginationSpeed : 400,
        singleItem:true,
        // Responsive
        responsive: true,
        responsiveRefreshRate : 200,
        responsiveBaseWidth: window
      });

      $("body.section-big-day .view-content").owlCarousel({
        autoPlay: 5000,
        navigation : false, // Show next and prev buttons
        slideSpeed : 300,
        paginationSpeed : 400,
        singleItem:true,
        // Responsive
        responsive: true,
        responsiveRefreshRate : 200,
        responsiveBaseWidth: window
      });


    });




  }
};


})(jQuery, Drupal, this, this.document);
