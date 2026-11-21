<?php
/**
 * Plugin Name: MonerousD for WooCommerce
 * Description: Take MonerousD (private digital dollars) at checkout. Plain payments are final like cash; protected payments are held in a vault until the buyer hands over a code, and return to the buyer by themselves if the order never arrives. No processor, no chargebacks, no account.
 * Version: 1.0.0
 * Requires PHP: 7.4
 * Requires Plugins: woocommerce
 * License: Apache-2.0
 * License URI: https://www.apache.org/licenses/LICENSE-2.0
 *
 * Copyright (c) 2026, The MoneroUSD Protocol
 *
 * This plugin talks only to the MonerousD checkout helper the shop runs itself (musd_checkout.py), which talks to
 * the shop's own wallet. The plugin holds no key and decides nothing: an order is paid when the helper, asked by
 * this plugin, says the shop's own wallet saw the money. A buyer's browser is never the source of that answer.
 */

defined('ABSPATH') || exit;

add_action('before_woocommerce_init', function () {
    if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});

add_filter('woocommerce_payment_gateways', function ($gateways) {
    $gateways[] = 'WC_Gateway_MonerousD';
    return $gateways;
});

add_action('plugins_loaded', function () {
    if (!class_exists('WC_Payment_Gateway')) {
        return;
    }

    class WC_Gateway_MonerousD extends WC_Payment_Gateway
    {
        const LINK = '/^monerousd:pay\?h=[A-Za-z0-9.:_-]{1,128}&t=[A-Za-z0-9_-]{1,128}$/';

        public function __construct()
        {
            $this->id = 'monerousd';
            $this->method_title = 'MonerousD';
            $this->method_description = 'Private digital dollars, paid from the buyer\'s MonerousD wallet straight to yours. Needs the MonerousD checkout helper running beside your wallet.';
            $this->has_fields = false;
            $this->supports = array('products');
            $this->init_form_fields();
            $this->init_settings();
            $this->title = $this->get_option('title', 'MonerousD');
            $this->description = $this->get_option('description');

            add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
            add_action('woocommerce_receipt_' . $this->id, array($this, 'pay_panel'));
            add_action('woocommerce_thankyou_' . $this->id, array($this, 'pay_panel'));
            add_action('woocommerce_view_order', array($this, 'pay_panel_if_ours'));
            add_action('woocommerce_api_monerousd_status', array($this, 'api_status'));
            add_action('woocommerce_api_monerousd_code', array($this, 'api_code'));
            add_action('woocommerce_api_monerousd_webhook', array($this, 'api_webhook'));
            add_action('woocommerce_order_status_cancelled', array($this, 'order_cancelled'));
        }

        public function init_form_fields()
        {
            $this->form_fields = array(
                'enabled' => array('title' => 'Enable', 'type' => 'checkbox', 'label' => 'Take MonerousD at checkout', 'default' => 'no'),
                'title' => array('title' => 'Name at checkout', 'type' => 'text', 'default' => 'MonerousD'),
                'description' => array('title' => 'Line under the name', 'type' => 'text', 'default' => 'Pay privately from your MonerousD wallet.'),
                'helper_url' => array('title' => 'Checkout helper address', 'type' => 'text', 'default' => 'http://127.0.0.1:8787', 'description' => 'Where your musd_checkout.py listens. Keep it on this machine or your private network.'),
                'api_key' => array('title' => 'Checkout key', 'type' => 'password', 'description' => 'The api_key from your helper\'s config.'),
                'webhook_secret' => array('title' => 'Webhook secret', 'type' => 'password', 'description' => 'The webhook_secret from your helper\'s config. Set the helper\'s webhook_url to: ' . esc_html(WC()->api_request_url('monerousd_webhook'))),
                'mode' => array(
                    'title' => 'How orders are paid', 'type' => 'select', 'default' => 'pay_now',
                    'options' => array(
                        'pay_now' => 'Plain payment: final at once, like cash',
                        'protected' => 'Protected: held until the buyer hands over a code; back to the buyer after the deadline',
                    ),
                ),
                'deadline_hours' => array('title' => 'Protected deadline (hours)', 'type' => 'number', 'default' => '336', 'description' => 'How long a protected payment waits for the buyer\'s code before it returns to the buyer. Leave room for delivery: 336 is two weeks.'),
            );
        }

        public function is_available()
        {
            // one MonerousD dollar is one US dollar: a shop priced in another currency would charge the wrong amount
            return parent::is_available() && get_woocommerce_currency() === 'USD' && $this->get_option('api_key') !== '';
        }

        /** One call to the shop's own helper. Returns array(http code, decoded body). */
        private function helper($method, $path, $body = null)
        {
            $args = array(
                'method' => $method,
                'timeout' => 20,
                'headers' => array('X-Checkout-Key' => $this->get_option('api_key'), 'Content-Type' => 'application/json'),
            );
            if ($body !== null) {
                $args['body'] = wp_json_encode($body);
            }
            $reply = wp_remote_request(untrailingslashit($this->get_option('helper_url')) . $path, $args);
            if (is_wp_error($reply)) {
                return array(0, array('error' => 'the checkout helper could not be reached'));
            }
            $decoded = json_decode(wp_remote_retrieve_body($reply), true);
            return array((int) wp_remote_retrieve_response_code($reply), is_array($decoded) ? $decoded : array());
        }

        private function keep($order, $view)
        {
            foreach (array('order_id', 'state', 'link', 'token', 'mode', 'refund_code') as $k) {
                if (isset($view[$k])) {
                    $order->update_meta_data('_musd_' . $k, $view[$k]);
                }
            }
            $order->save();
        }

        public function process_payment($order_id)
        {
            $order = wc_get_order($order_id);
            if ($order->get_meta('_musd_order_id') === '' || abs((float) $order->get_meta('_musd_total') - (float) $order->get_total()) > 0.000001) {
                list($code, $view) = $this->helper('POST', '/v1/orders', array(
                    'reference' => (string) $order->get_id(),
                    'title' => 'Order ' . $order->get_order_number(),
                    'amount' => wc_format_decimal($order->get_total(), 8),
                    'mode' => $this->get_option('mode', 'pay_now'),
                    'deadline_hours' => (int) $this->get_option('deadline_hours', 336),
                ));
                if ($code !== 200 || empty($view['order_id'])) {
                    wc_add_notice('MonerousD is not available right now. Nothing was charged. Please try again in a moment.', 'error');
                    return array('result' => 'failure');
                }
                $order->update_meta_data('_musd_total', $order->get_total());
                $this->keep($order, $view);
            }
            $order->update_status('pending', 'Waiting for the MonerousD payment.');
            return array('result' => 'success', 'redirect' => $order->get_checkout_payment_url(true));
        }

        /** Ask the helper where the order stands and move the WooCommerce order to match. The helper's answer is its
         *  wallet's; nothing a browser sends is believed. */
        private function sync($order)
        {
            $id = $order->get_meta('_musd_order_id');
            if ($id === '') {
                return array('status' => 'none');
            }
            list($code, $view) = $this->helper('GET', '/v1/orders/' . rawurlencode($id) . '/status');
            if ($code === 404) {
                // the helper restarted: this order's own stored state brings it back
                list($code, $view) = $this->helper('POST', '/v1/orders/import', array('state' => $order->get_meta('_musd_state')));
            }
            if ($code !== 200 || empty($view['status'])) {
                return array('status' => 'unknown');
            }
            $this->keep($order, $view);
            if ($view['status'] === 'paid' && !$order->is_paid()) {
                $order->payment_complete($id);
                $order->add_order_note('MonerousD: paid. The money is in your wallet.');
            } elseif ($view['status'] === 'locked' && $order->has_status(array('pending', 'failed'))) {
                $order->update_status('on-hold', 'MonerousD: the payment is held in the buyer\'s vault for this order. Ship now. You are paid when the buyer hands over the code; if no code comes by the deadline the money returns to the buyer.');
                wc_reduce_stock_levels($order->get_id());
            } elseif ($view['status'] === 'expired' && $order->has_status('pending')) {
                $order->update_status('failed', 'MonerousD: no payment arrived in time.');
            }
            return $view;
        }

        public function pay_panel_if_ours($order_id)
        {
            $order = wc_get_order($order_id);
            if ($order && $order->get_payment_method() === $this->id) {
                $this->pay_panel($order_id);
            }
        }

        public function pay_panel($order_id)
        {
            static $shown = array();
            $order = wc_get_order($order_id);
            if (!$order || isset($shown[$order_id]) || $order->get_meta('_musd_order_id') === '') {
                return;
            }
            $shown[$order_id] = true;
            $view = $this->sync($order);
            $can_pay = in_array($view['status'], array('open', 'accepted'), true);
            $link = (string) $order->get_meta('_musd_link');
            if (!preg_match(self::LINK, $link)) {
                echo '<p>' . esc_html('MonerousD is not available for this order right now.') . '</p>';
                return;
            }
            $protected = $order->get_meta('_musd_mode') === 'protected';
            $query = array('order' => $order->get_id(), 'key' => $order->get_order_key());
            $promise = $protected
                ? 'Your payment is held in escrow until you confirm receipt. If your order is not delivered, it is refunded automatically.'
                : 'This payment is final the moment it lands, like cash.';
            ?>
            <section id="musd" style="max-width:28rem;border:1px solid #d2d2d7;border-radius:14px;padding:1.5rem;margin:1rem 0">
                <h3 style="margin-top:0"><?php echo esc_html('Pay with MonerousD'); ?></h3>
                <p><?php echo esc_html($promise); ?></p>
                <p id="musd-pay"<?php echo $can_pay ? '' : ' hidden'; ?>><a class="button alt" href="<?php echo esc_attr($link); ?>"><?php echo esc_html('Open my wallet and pay'); ?></a></p>
                <p id="musd-copy"<?php echo $can_pay ? '' : ' hidden'; ?> style="font-size:.85em;color:#6e6e73"><?php echo esc_html('Wallet on another device? Copy this into it:'); ?><br><code style="word-break:break-all"><?php echo esc_html($link); ?></code></p>
                <p><?php echo esc_html('Status:'); ?> <strong id="musd-status"></strong></p>
                <form id="musd-code" hidden>
                    <p style="font-size:.85em;color:#6e6e73"><?php echo esc_html('Received your order? Tap Confirm receipt in your wallet, or enter your release code here.'); ?></p>
                    <input id="musd-code-text" autocomplete="off" placeholder="<?php echo esc_attr('Handover code'); ?>" style="width:100%">
                    <p><button class="button alt" type="submit"><?php echo esc_html('I have my order'); ?></button></p>
                </form>
                <p id="musd-refund" hidden style="font-size:.85em"><?php echo esc_html('This order was cancelled. Your wallet claims the refund automatically; if it is closed, open it and enter this refund code on the Wallet page:'); ?><br><code id="musd-refund-code" style="word-break:break-all"></code></p>
            </section>
            <script>
            (function () {
                var statusUrl = <?php echo wp_json_encode(add_query_arg($query, WC()->api_request_url('monerousd_status'))); ?>;
                var codeUrl = <?php echo wp_json_encode(add_query_arg($query, WC()->api_request_url('monerousd_code'))); ?>;
                var words = {open: 'waiting for payment', accepted: 'waiting for payment', locked: 'payment held safely', paid: 'paid. Thank you.', cancelled: 'cancelled', expired: 'expired', unknown: 'checking…'};
                var first = <?php echo wp_json_encode(isset($view['status']) ? $view['status'] : 'unknown'); ?>;
                var wasOpen = first === 'open' || first === 'accepted';
                function show(j) {
                    document.getElementById('musd-status').textContent = words[j.status] || j.status;
                    var open = j.status === 'open' || j.status === 'accepted';
                    document.getElementById('musd-pay').hidden = !open;
                    document.getElementById('musd-copy').hidden = !open;
                    document.getElementById('musd-code').hidden = j.status !== 'locked';
                    if (j.refund_code) {
                        document.getElementById('musd-refund').hidden = false;
                        document.getElementById('musd-refund-code').textContent = j.refund_code;
                    }
                    if (wasOpen && j.status === 'paid' && j.next) { location.href = j.next; }
                }
                function tick() {
                    fetch(statusUrl, {credentials: 'same-origin'}).then(function (r) { return r.json(); }).then(show).catch(function () {}).then(function () { setTimeout(tick, 4000); });
                }
                document.getElementById('musd-code').addEventListener('submit', function (e) {
                    e.preventDefault();
                    fetch(codeUrl, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({code: document.getElementById('musd-code-text').value})})
                        .then(function (r) { return r.json(); }).then(function (j) { if (j.error) { alert(j.error); } else { show(j); } });
                });
                show({status: first});
                tick();
            })();
            </script>
            <?php
        }

        /** The order this request may see: its id AND its own secret key, as WooCommerce's order pages require. */
        private function order_of_request()
        {
            $order = wc_get_order(absint(isset($_GET['order']) ? $_GET['order'] : 0));
            $key = isset($_GET['key']) ? sanitize_text_field(wp_unslash($_GET['key'])) : '';
            if (!$order || $order->get_payment_method() !== $this->id || !$order->key_is_valid($key)) {
                wp_send_json(array('error' => 'no such order'), 404);
            }
            return $order;
        }

        public function api_status()
        {
            $order = $this->order_of_request();
            $view = $this->sync($order);
            wp_send_json(array(
                'status' => isset($view['status']) ? $view['status'] : 'unknown',
                'refund_code' => isset($view['refund_code']) ? $view['refund_code'] : null,
                'next' => $this->get_return_url($order),
            ));
        }

        public function api_code()
        {
            $order = $this->order_of_request();
            $body = json_decode(file_get_contents('php://input'), true);
            $code = is_array($body) && isset($body['code']) ? trim((string) $body['code']) : '';
            if (!preg_match('/^[0-9a-f]{32}:[0-9a-f]{8,128}$/', $code)) {
                wp_send_json(array('error' => 'That is not a handover code.'), 400);
            }
            $this->sync($order);
            list($http, $view) = $this->helper('POST', '/v1/orders/' . rawurlencode($order->get_meta('_musd_order_id')) . '/code', array('code' => $code));
            if ($http !== 200) {
                wp_send_json(array('error' => isset($view['error']) ? $view['error'] : 'The code was not accepted.'), 400);
            }
            $view = $this->sync($order);
            wp_send_json(array('status' => isset($view['status']) ? $view['status'] : 'unknown'));
        }

        public function api_webhook()
        {
            $body = file_get_contents('php://input');
            $secret = $this->get_option('webhook_secret');
            $given = isset($_SERVER['HTTP_X_MUSD_SIGNATURE']) ? (string) $_SERVER['HTTP_X_MUSD_SIGNATURE'] : '';
            if ($secret === '' || !hash_equals(hash('sha3-256', $secret . $body), $given)) {
                status_header(401);
                exit;
            }
            $event = json_decode($body, true);
            $order = wc_get_order(absint(isset($event['reference']) ? $event['reference'] : 0));
            // the webhook only says "look now": the order moves on what the helper answers when asked
            if ($order && $order->get_payment_method() === $this->id && $order->get_meta('_musd_order_id') === (isset($event['order_id']) ? $event['order_id'] : null)) {
                $this->sync($order);
            }
            status_header(200);
            exit;
        }

        public function order_cancelled($order_id)
        {
            $order = wc_get_order($order_id);
            if (!$order || $order->get_payment_method() !== $this->id || $order->get_meta('_musd_order_id') === '') {
                return;
            }
            $this->sync($order);
            list($code, $view) = $this->helper('POST', '/v1/orders/' . rawurlencode($order->get_meta('_musd_order_id')) . '/cancel', array());
            if ($code === 200) {
                $this->keep($order, $view);
                if (!empty($view['refund_code'])) {
                    $order->add_order_note('MonerousD: sale cancelled. The buyer\'s wallet claims the refund automatically; the refund code is on the buyer\'s order page.');
                }
            }
        }
    }
});
