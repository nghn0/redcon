import { useState, useCallback } from 'react';
import { createScope, getScope } from '../hooks/useApi';
import type { ScopeData } from '../hooks/useApi';
import { AlertIcon, CheckIcon, InfoIcon, TargetIcon, LockIcon } from './icons';

const ATTACK_CLASSES = [
  { value: 'recon', label: 'Recon / OSINT' },
  { value: 'web', label: 'Web Application' },
  { value: 'network', label: 'Network' },
  { value: 'exploitation', label: 'Exploitation' },
  { value: 'social_eng', label: 'Social Engineering' },
  { value: 'mitm', label: 'MITM' },
];

const IP_CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const DOMAIN_RE = /^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function isValidTarget(t: string): boolean {
  const v = t.trim();
  if (!v) return false;
  if (IP_CIDR_RE.test(v)) {
    const parts = v.split('/');
    const octets = parts[0].split('.').map(Number);
    if (octets.some(o => o < 0 || o > 255)) return false;
    if (parts[1]) {
      const mask = parseInt(parts[1]);
      if (mask < 0 || mask > 32) return false;
    }
    return true;
  }
  return DOMAIN_RE.test(v);
}

interface FormData {
  engagement_id: string;
  engagement_name: string;
  targets: string;
  excluded_targets: string;
  start_time: string;
  end_time: string;
  allowed_attack_classes: string[];
  auth_name: string;
  auth_email: string;
  auth_role: string;
  emergency_contact: string;
  rate_limit: string;
  notify_before_exploit: boolean;
}

interface FieldErrors {
  [key: string]: string;
}

function toDatetimeLocal(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const EMPTY_FORM: FormData = {
  engagement_id: '',
  engagement_name: '',
  targets: '',
  excluded_targets: '',
  start_time: toDatetimeLocal(new Date()),
  end_time: toDatetimeLocal(new Date(Date.now() + 7 * 86400000)),
  allowed_attack_classes: [],
  auth_name: '',
  auth_email: '',
  auth_role: '',
  emergency_contact: '',
  rate_limit: '',
  notify_before_exploit: false,
};

export function ScopeForm({ onCreated }: { onCreated: (scope: ScopeData) => void }) {
  const [form, setForm] = useState<FormData>({ ...EMPTY_FORM });
  const [errors, setErrors] = useState<FieldErrors>({});
  const [submitting, setSubmitting] = useState(false);
  const [serverError, setServerError] = useState('');
  const [existingEngagement, setExistingEngagement] = useState<ScopeData | null>(null);
  const [existingLoaded, setExistingLoaded] = useState(false);

  const validateField = useCallback((field: keyof FormData, value: any): string | null => {
    switch (field) {
      case 'targets': {
        const targets = (value as string).split('\n').map(s => s.trim()).filter(Boolean);
        if (targets.length === 0) return 'At least one target is required';
        const bad = targets.filter(t => !isValidTarget(t));
        if (bad.length) return `Invalid targets: ${bad.join(', ')}`;
        return null;
      }
      case 'excluded_targets': {
        const excluded = (value as string).split('\n').map(s => s.trim()).filter(Boolean);
        if (excluded.length) {
          const bad = excluded.filter(t => !isValidTarget(t));
          if (bad.length) return `Invalid excluded targets: ${bad.join(', ')}`;
        }
        return null;
      }
      case 'end_time': {
        const start = form.start_time;
        const end = value as string;
        if (!start || !end) return 'Start and end times are required';
        if (new Date(end) <= new Date(start)) return 'End time must be after start time';
        return null;
      }
      case 'engagement_id': {
        if (!(value as string).trim()) return 'Engagement ID is required';
        return null;
      }
      case 'engagement_name': {
        if (!(value as string).trim()) return 'Engagement name is required';
        return null;
      }
      case 'allowed_attack_classes': {
        if (!(value as string[]).length) return 'Select at least one attack class';
        return null;
      }
      case 'auth_name': {
        if (!(value as string).trim()) return 'Required';
        return null;
      }
      case 'auth_email': {
        if (!(value as string).trim()) return 'Required';
        return null;
      }
      case 'auth_role': {
        if (!(value as string).trim()) return 'Required';
        return null;
      }
      case 'emergency_contact': {
        if (!(value as string).trim()) return 'Required';
        return null;
      }
      case 'rate_limit': {
        if (value) {
          const n = parseInt(value as string);
          if (isNaN(n) || n < 1) return 'Must be a positive integer';
        }
        return null;
      }
      default:
        return null;
    }
  }, [form.start_time]);

  const validate = useCallback((): FieldErrors => {
    const e: FieldErrors = {};

    const idErr = validateField('engagement_id', form.engagement_id);
    if (idErr) e.engagement_id = idErr;

    const nameErr = validateField('engagement_name', form.engagement_name);
    if (nameErr) e.engagement_name = nameErr;

    const targetsErr = validateField('targets', form.targets);
    if (targetsErr) e.targets = targetsErr;

    const excludedErr = validateField('excluded_targets', form.excluded_targets);
    if (excludedErr) e.excluded_targets = excludedErr;

    const classesErr = validateField('allowed_attack_classes', form.allowed_attack_classes);
    if (classesErr) e.allowed_attack_classes = classesErr;

    const endErr = validateField('end_time', form.end_time);
    if (endErr) e.end_time = endErr;

    const authNameErr = validateField('auth_name', form.auth_name);
    if (authNameErr) e.auth_name = authNameErr;

    const authEmailErr = validateField('auth_email', form.auth_email);
    if (authEmailErr) e.auth_email = authEmailErr;

    const authRoleErr = validateField('auth_role', form.auth_role);
    if (authRoleErr) e.auth_role = authRoleErr;

    const emergErr = validateField('emergency_contact', form.emergency_contact);
    if (emergErr) e.emergency_contact = emergErr;

    const rateErr = validateField('rate_limit', form.rate_limit);
    if (rateErr) e.rate_limit = rateErr;

    return e;
  }, [form, validateField]);

  const runFieldValidation = useCallback((field: keyof FormData, value: any) => {
    const error = validateField(field, value);
    setErrors(prev => {
      const next = { ...prev };
      if (error) next[field] = error;
      else delete next[field];
      return next;
    });
  }, [validateField]);

  const set = (field: keyof FormData, value: any) => {
    setForm(prev => ({ ...prev, [field]: value }));
    setExistingLoaded(false);
    runFieldValidation(field, value);
  };

  const handleBlur = (field: keyof FormData) => {
    runFieldValidation(field, form[field]);
  };

  const handleEngagementBlur = async () => {
    const id = form.engagement_id.trim();
    if (!id) return;

    runFieldValidation('engagement_id', id);

    try {
      const existing = await getScope(id);
      if (existing) {
        const newForm: FormData = {
          engagement_id: existing.engagement_id,
          engagement_name: existing.engagement_name,
          targets: existing.targets.join('\n'),
          excluded_targets: existing.excluded_targets.join('\n'),
          start_time: toDatetimeLocal(new Date(existing.start_time)),
          end_time: toDatetimeLocal(new Date(existing.end_time)),
          allowed_attack_classes: [...existing.allowed_attack_classes],
          auth_name: existing.authorization_contact.name,
          auth_email: existing.authorization_contact.email,
          auth_role: existing.authorization_contact.role,
          emergency_contact: existing.emergency_contact,
          rate_limit: existing.rate_limit?.toString() ?? '',
          notify_before_exploit: existing.notify_before_exploit ?? false,
        };
        setForm(newForm);
        setExistingEngagement(existing);
        setExistingLoaded(true);
        setErrors({});
      }
    } catch {
      setExistingEngagement(null);
      setExistingLoaded(false);
    }
  };

  const handleEngagementChange = (value: string) => {
    setForm(prev => ({ ...prev, engagement_id: value }));
    setExistingEngagement(null);
    setExistingLoaded(false);
    setErrors(prev => {
      const next = { ...prev };
      delete next.engagement_id;
      return next;
    });
  };

  const toggleClass = (cls: string) => {
    setForm(prev => {
      const updated = prev.allowed_attack_classes.includes(cls)
        ? prev.allowed_attack_classes.filter(c => c !== cls)
        : [...prev.allowed_attack_classes, cls];
      runFieldValidation('allowed_attack_classes', updated);
      return { ...prev, allowed_attack_classes: updated };
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const errs = validate();
    setErrors(errs);
    if (Object.keys(errs).length) return;

    setSubmitting(true);
    setServerError('');

    try {
      const scope = await createScope({
        engagement_id: form.engagement_id.trim(),
        engagement_name: form.engagement_name.trim(),
        targets: form.targets.split('\n').map(s => s.trim()).filter(Boolean),
        excluded_targets: form.excluded_targets.split('\n').map(s => s.trim()).filter(Boolean),
        start_time: new Date(form.start_time).toISOString(),
        end_time: new Date(form.end_time).toISOString(),
        allowed_attack_classes: form.allowed_attack_classes,
        authorization_contact: {
          name: form.auth_name.trim(),
          email: form.auth_email.trim(),
          role: form.auth_role.trim(),
        },
        emergency_contact: form.emergency_contact.trim(),
        rate_limit: form.rate_limit ? parseInt(form.rate_limit) : null,
        notify_before_exploit: form.notify_before_exploit || null,
      });
      onCreated(scope);
    } catch (err: any) {
      setServerError(err.message || 'Failed to create scope');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="section-head">
        <div>
          <h1>New Engagement Scope</h1>
          <p className="section-desc">
            Define the legal and contractual boundary of the engagement. The scope file is
            immutable once created — edits create a new version.
          </p>
        </div>
      </div>

      {existingEngagement && existingLoaded && (
        <div className="existing-banner">
          <InfoIcon />
          <span>
            Existing engagement found — editing will create version{' '}
            <strong>v{existingEngagement.version + 1}</strong>
          </span>
        </div>
      )}

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">Engagement Details</span>
        </div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-1">
              <label htmlFor="engagement_id">
                Engagement ID <span className="req">*</span>
              </label>
              <div className="input-with-indicator">
                <input
                  id="engagement_id"
                  type="text"
                  className={`input ${errors.engagement_id ? 'error' : ''} ${existingEngagement && existingLoaded ? 'existing' : ''}`}
                  value={form.engagement_id}
                  onChange={e => handleEngagementChange(e.target.value)}
                  onBlur={handleEngagementBlur}
                  placeholder="e.g. eng-2025-001"
                />
              </div>
              {errors.engagement_id && <span className="field-error">{errors.engagement_id}</span>}
            </div>
            <div className="form-group flex-1">
              <label htmlFor="engagement_name">
                Engagement Name <span className="req">*</span>
              </label>
              <input
                id="engagement_name"
                type="text"
                className={`input ${errors.engagement_name ? 'error' : ''}`}
                value={form.engagement_name}
                onChange={e => set('engagement_name', e.target.value)}
                onBlur={() => handleBlur('engagement_name')}
                placeholder="e.g. Client A - External Perimeter"
              />
              {errors.engagement_name && <span className="field-error">{errors.engagement_name}</span>}
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">
            <TargetIcon />
            Targets
          </span>
        </div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-1">
              <label htmlFor="targets">
                In-Scope Targets <span className="req">*</span>{' '}
                <span className="label-hint">(one per line — IP, CIDR, or domain)</span>
              </label>
              <textarea
                id="targets"
                rows={5}
                className={`input mono ${errors.targets ? 'error' : ''}`}
                value={form.targets}
                onChange={e => set('targets', e.target.value)}
                onBlur={() => handleBlur('targets')}
                placeholder={'203.0.113.0/24\nexample.com\n192.168.1.100'}
              />
              {errors.targets && <span className="field-error">{errors.targets}</span>}
            </div>
            <div className="form-group flex-1">
              <label htmlFor="excluded_targets">
                Excluded Targets <span className="label-hint">(one per line)</span>
              </label>
              <textarea
                id="excluded_targets"
                rows={5}
                className={`input mono ${errors.excluded_targets ? 'error' : ''}`}
                value={form.excluded_targets}
                onChange={e => set('excluded_targets', e.target.value)}
                onBlur={() => handleBlur('excluded_targets')}
                placeholder={'203.0.113.50\nadmin.example.com'}
              />
              {errors.excluded_targets && <span className="field-error">{errors.excluded_targets}</span>}
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">
            <LockIcon />
            Authorization Window
          </span>
        </div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-1">
              <label htmlFor="start_time">Start Time</label>
              <input
                id="start_time"
                type="datetime-local"
                className="input"
                value={form.start_time}
                onChange={e => set('start_time', e.target.value)}
              />
            </div>
            <div className="form-group flex-1">
              <label htmlFor="end_time">End Time</label>
              <input
                id="end_time"
                type="datetime-local"
                className={`input ${errors.end_time ? 'error' : ''}`}
                value={form.end_time}
                onChange={e => set('end_time', e.target.value)}
                onBlur={() => handleBlur('end_time')}
              />
              {errors.end_time && <span className="field-error">{errors.end_time}</span>}
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">Attack Classes</span>
        </div>
        <div className="card-body">
          {errors.allowed_attack_classes && (
            <span className="field-error" style={{ marginBottom: 8, display: 'block' }}>
              {errors.allowed_attack_classes}
            </span>
          )}
          <div className="checkbox-group">
            {ATTACK_CLASSES.map(ac => (
              <label
                key={ac.value}
                className={`checkbox-label ${form.allowed_attack_classes.includes(ac.value) ? 'checked' : ''}`}
              >
                <input
                  type="checkbox"
                  checked={form.allowed_attack_classes.includes(ac.value)}
                  onChange={() => toggleClass(ac.value)}
                />
                <span className="box">
                  <CheckIcon />
                </span>
                <span>{ac.label}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">Authorization &amp; Emergency Contacts</span>
        </div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-1">
              <label htmlFor="auth_name">
                Authorizer Name <span className="req">*</span>
              </label>
              <input
                id="auth_name"
                type="text"
                className={`input ${errors.auth_name ? 'error' : ''}`}
                value={form.auth_name}
                onChange={e => set('auth_name', e.target.value)}
                onBlur={() => handleBlur('auth_name')}
              />
              {errors.auth_name && <span className="field-error">{errors.auth_name}</span>}
            </div>
            <div className="form-group flex-1">
              <label htmlFor="auth_email">
                Authorizer Email <span className="req">*</span>
              </label>
              <input
                id="auth_email"
                type="email"
                className={`input ${errors.auth_email ? 'error' : ''}`}
                value={form.auth_email}
                onChange={e => set('auth_email', e.target.value)}
                onBlur={() => handleBlur('auth_email')}
              />
              {errors.auth_email && <span className="field-error">{errors.auth_email}</span>}
            </div>
            <div className="form-group flex-1">
              <label htmlFor="auth_role">
                Authorizer Role <span className="req">*</span>
              </label>
              <input
                id="auth_role"
                type="text"
                className={`input ${errors.auth_role ? 'error' : ''}`}
                value={form.auth_role}
                onChange={e => set('auth_role', e.target.value)}
                onBlur={() => handleBlur('auth_role')}
                placeholder="e.g. CISO"
              />
              {errors.auth_role && <span className="field-error">{errors.auth_role}</span>}
            </div>
          </div>
          <div className="form-row" style={{ marginTop: 16 }}>
            <div className="form-group flex-1">
              <label htmlFor="emergency_contact">
                Emergency Contact <span className="req">*</span>
              </label>
              <input
                id="emergency_contact"
                type="text"
                className={`input ${errors.emergency_contact ? 'error' : ''}`}
                value={form.emergency_contact}
                onChange={e => set('emergency_contact', e.target.value)}
                onBlur={() => handleBlur('emergency_contact')}
                placeholder="Name (phone/email)"
              />
              {errors.emergency_contact && <span className="field-error">{errors.emergency_contact}</span>}
            </div>
            <div className="form-group">
              <label htmlFor="rate_limit">Rate Limit <span className="label-hint">(req/s, optional)</span></label>
              <input
                id="rate_limit"
                type="number"
                min="1"
                className={`input ${errors.rate_limit ? 'error' : ''}`}
                value={form.rate_limit}
                onChange={e => set('rate_limit', e.target.value)}
                onBlur={() => handleBlur('rate_limit')}
                placeholder="e.g. 100"
              />
              {errors.rate_limit && <span className="field-error">{errors.rate_limit}</span>}
            </div>
            <div className="form-group" style={{ justifyContent: 'flex-end' }}>
              <label className="checkbox-label" style={{ marginTop: 26, marginBottom: 0 }}>
                <input
                  type="checkbox"
                  checked={form.notify_before_exploit}
                  onChange={e => {
                    setForm(prev => ({ ...prev, notify_before_exploit: e.target.checked }));
                  }}
                />
                <span className="box">
                  <CheckIcon />
                </span>
                <span>Notify before exploit</span>
              </label>
            </div>
          </div>
        </div>
      </div>

      {serverError && (
        <div className="server-error">
          <AlertIcon />
          <span>{serverError}</span>
        </div>
      )}

      <button type="submit" className="btn btn-primary btn-lg" disabled={submitting}>
        {submitting ? (
          <>
            <span className="spinner" />
            Creating…
          </>
        ) : existingEngagement && existingLoaded ? (
          `Create Version ${existingEngagement.version + 1}`
        ) : (
          'Create Scope File'
        )}
      </button>
    </form>
  );
}
