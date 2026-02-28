import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY || '';

if (!supabaseUrl || !supabaseKey) {
    console.warn("Missing Supabase environment variables. Please add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to your .env file.");
}

export const supabase = createClient(supabaseUrl, supabaseKey);
