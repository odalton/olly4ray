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




  Drupal.behaviors.bg_images_module = {

    attach: function (context, settings) {

      if(Drupal.settings.backstretch.key != 'empty') {
//
        console.log(settings.backstretch.key);
        $.backstretch(settings.backstretch.key);
//      } else {
//
//        var $hero = '#hero-header';
//        $('body').append('<img src='+ settings.backstretch.key +'>');
//
//
//        //console.log(settings.backstretch.key);
//        //console.log(settings.backstretch.path);
//        //$.backstretch(settings.backstretch.key);
//        //$('#hero-header').backstretch(settings.backstretch.key, {duration: 10000, fade: 750});
      }



    }
  };






})(jQuery, Drupal, this, this.document);
