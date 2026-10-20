const express = require('express');
const router = express.Router();

router.post('/stripe/webhook', express.json(), async (req, res) => {
  const event = JSON.parse(req.body);
  if (event.type === 'charge.succeeded') {
    await markPaid(event.data.object.metadata.orderId);
  }
  res.json({ received: true });
});

const stripe = require('stripe')('sk_test_51Fake...');
const WEBHOOK_SECRET = 'whsec_FAKE0000FAKE0000FAKE0000FAKE0000';

module.exports = router;