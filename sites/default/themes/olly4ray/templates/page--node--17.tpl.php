<?php
/**
 * @file
 * Returns the HTML for a single Drupal page.
 *
 * Complete documentation for this file is available online.
 * @see https://drupal.org/node/1728148
 */
?>


<div id="page">

  <!-- -->

  <div class="container">
    <ul id="gn-menu" class="gn-menu-main">
      <li class="gn-trigger">
        <a class="trigger gn-icon gn-icon-menu"><span>Menu</span></a>
        <nav class="gn-menu-wrapper">
          <div class="gn-scroller">
            <ul class="gn-menu">

              <?php if ($main_menu): ?>

              <?php
              print theme('links__system_main_menu', array(
                'links' => $main_menu,
                'attributes' => array(
                  'class' => array('gn-menu', 'inline', 'clearfix'),
                ),
                'heading' => array(
                  'text' => t('Main menu'),
                  'level' => 'h2',
                  'class' => array('element-invisible'),
                ),
              )); ?>
              <?php endif; ?>

            </ul>
          </div><!-- /gn-scroller -->
        </nav>
      </li>
<!--      <li>-->
<!--        <a class="tagline" href="">Oliver & Rachel</a>-->
<!--        <span class="tagline">are getting married...</span>-->
<!--      </li>-->
    </ul>

  </div><!-- /container -->

  <div class="menu-tagline">
    <a class="tagline" href="">Oliver & Rachel</a>
    <span class="tagline">are getting married...</span>
  </div>

  <!-- -->







  <div id="main">

    <div id="content" class="column" role="main">
      <?php print render($page['highlighted']); ?>
      <?php print $breadcrumb; ?>
      <a id="main-content"></a>
      <?php print render($title_prefix); ?>
      <?php if ($title): ?>
        <h1 class="page__title title" id="page-title"><?php print $title; ?></h1>
      <?php endif; ?>
      <?php print render($title_suffix); ?>
      <?php print $messages; ?>
      <?php print render($tabs); ?>
      <?php print render($page['help']); ?>
      <?php if ($action_links): ?>
        <ul class="action-links"><?php print render($action_links); ?></ul>
      <?php endif; ?>

      <div class="carousel">
        <?php
        $view = views_get_view('the_big_day');
        print $view->preview('default');
        ?>

      </div>

      <?php print render($page['content']); ?>
      <?php print $feed_icons; ?>
    </div>


    <?php
      // Render the sidebars to see if there's anything in them.
      $sidebar_first  = render($page['sidebar_first']);
      $sidebar_second = render($page['sidebar_second']);
    ?>

    <?php if ($sidebar_first || $sidebar_second): ?>
      <aside class="sidebars">
        <?php print $sidebar_first; ?>
        <?php print $sidebar_second; ?>
      </aside>
    <?php endif; ?>

  </div>

  <?php print render($page['footer']); ?>

</div>

<?php print render($page['bottom']); ?>
