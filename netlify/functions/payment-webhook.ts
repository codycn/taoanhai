import type { Handler, HandlerEvent } from "@netlify/functions";
import { supabaseAdmin } from './utils/supabaseClient';
import crypto from 'crypto';

const PAYOS_CHECKSUM_KEY = process.env.PAYOS_CHECKSUM_KEY;

const createSignature = (data: Record<string, any>, checksumKey: string): string => {
    const sortedKeys = Object.keys(data).sort();
    const dataString = sortedKeys.map(key => `${key}=${data[key]}`).join('&');
    return crypto.createHmac('sha256', checksumKey).update(dataString).digest('hex');
};

const handler: Handler = async (event: HandlerEvent) => {
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: JSON.stringify({ error: 'Method Not Allowed' }) };
    }

    // Check if this is a validation request from the app's frontend.
    // Such requests will be authenticated with the user's JWT.
    const authHeader = event.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
            if (!error && user) {
                // This is an authenticated test request from our own app.
                // We return 200 OK to confirm the webhook URL is live and reachable.
                console.log(`[INFO] Webhook validation request from user ${user.id} successful.`);
                return {
                    statusCode: 200,
                    body: JSON.stringify({ message: 'Webhook URL validation successful.' }),
                };
            }
        } catch (e) {
            // If token validation fails for any reason, fall through to PayOS validation.
            console.warn('[WARN] Error during app-internal webhook validation, proceeding to PayOS check.', e);
        }
    }

    // --- Standard PayOS Webhook Logic ---
    console.log("--- [START] PayOS Webhook Received ---");

    if (!PAYOS_CHECKSUM_KEY) {
        console.error('[FATAL] PAYOS_CHECKSUM_KEY is not set.');
        return { statusCode: 500, body: JSON.stringify({ error: 'Webhook configuration error.' }) };
    }
    
    try {
        const signatureFromHeader = event.headers['x-payos-signature'];
        const body = JSON.parse(event.body || '{}');
        const webhookData = body.data;

        if (!webhookData || !signatureFromHeader) {
            console.error("[VALIDATION_ERROR] Missing 'data' or 'x-payos-signature' header.");
            return { statusCode: 400, body: JSON.stringify({ error: 'Missing webhook data or signature.' }) };
        }
        
        const calculatedSignature = createSignature(webhookData, PAYOS_CHECKSUM_KEY);
        if (calculatedSignature !== signatureFromHeader) {
            console.warn(`[SECURITY_WARNING] Invalid signature.`);
            return { statusCode: 401, body: JSON.stringify({ error: 'Invalid signature.' }) };
        }
        console.log("[INFO] Signature validated successfully.");

        const { orderCode, status } = webhookData;
        const numericOrderCode = Number(orderCode);
        if (isNaN(numericOrderCode)) {
            return { statusCode: 400, body: JSON.stringify({ error: 'Invalid orderCode format.' }) };
        }
        
        const isSuccess = status?.toUpperCase() === 'PAID';
        const isFailure = status?.toUpperCase() === 'CANCELLED' || status?.toUpperCase() === 'FAILED';

        if (isSuccess) {
            // With manual approval, we just log this. The status remains 'pending'.
            console.log(`[INFO] Order ${numericOrderCode} is PAID. Awaiting admin approval.`);
        } else if (isFailure) {
            const dbStatus = status.toUpperCase() === 'CANCELLED' ? 'canceled' : 'failed';
            // Update the status for failed or canceled transactions
            await supabaseAdmin
               .from('transactions')
               .update({ status: dbStatus, updated_at: new Date().toISOString() })
               .eq('order_code', numericOrderCode)
               .eq('status', 'pending');
            console.log(`[INFO] Order ${numericOrderCode} marked as '${dbStatus}'.`);
        }

    } catch (error: any) {
        console.error(`[FATAL] Unhandled error in webhook:`, error.message);
        return { statusCode: 500, body: JSON.stringify({ error: 'Internal server error.' }) };
    }

    console.log("--- [END] Webhook Processed Successfully ---");
    // Always return 200 OK to PayOS to prevent retries.
    return { statusCode: 200, body: JSON.stringify({ message: 'Webhook received.' }) };
};

export { handler };