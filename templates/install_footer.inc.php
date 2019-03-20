        </div>
    <!-- /container -->
    <!-- Bootstrap core JavaScript
    ================================================== -->
    <script src="<?php echo $web_path; ?>/lib/components/jquery/jquery.min.js"></script>
    <script src="<?php echo $web_path; ?>/lib/components/bootstrap/js/bootstrap.min.js"></script>
    <script src="<?php echo $web_path; ?>/lib/javascript/base.js" type="text/javascript"></script>
    <script src="http://code.jquery.com/jquery-1.12.4.js"></script>
    <script src="http://code.jquery.com/jquery-migrate-1.4.1.js"></script>
    <?php
        if (isset($jsEnd) && !empty($jsEnd) && is_array($jsEnd)) {
            foreach ($jsEnd as $js) {
                echo $js;
            }
        }
    ?>
    </body>
</html>
