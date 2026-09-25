// Inference of user-generated content: comments, reviews, posts, answers.
// Used when a page has no policy, and to find user content a policy missed.

const CSS_IDENT = /^-?[_a-zA-Z][_a-zA-Z0-9-]*$/;

const UGC_NAME =
  /^(?:[a-z0-9]+[-_])*(comments?|commentlist|replies|reply|reviews?|user[-_]?(?:content|generated|comments?|reviews?|posts?)|ugc|discussions?|forum[-_]?posts?|guestbook|commtext|timeline[-_]comment|issue[-_](?:title|body)|markdown[-_]body|disqus)(?:[-_](?:list|body|content|text|thread|threads|section|area|wrapper|container|item|items|tree|message|entry|entries|block|region|root|panel|feed|holder))?$/i;
const NEGATIVE_PREFIX = /^(has|no|show|hide|toggle|load|more|add|write|leave|submit|open|close|closed|enable|disable|with|without|count|num|total|view|js[-_]toggle)[-_]/i;
const NEGATIVE_SUFFIX =
  /[-_](count|counter|link|links|button|btn|form|respond|toggle|icon|number|num|meta|open|closed|input|field|label|tab|nav|summary|stats|rating|ratings|stars?|score|author|avatar|date|time|actions?|header|heading|policy|guidelines)$/i;

const UGC_TAGS = {
  'shreddit-comment': 'Reddit comment',
  'shreddit-post': 'Reddit post',
  'ytd-comment-thread-renderer': 'YouTube comments',
  'ytd-comment-renderer': 'YouTube comment'
};
const SCHEMA_TYPE = /schema\.org\/(Comment|Review|UserComments|Answer|Question|DiscussionForumPosting|SocialMediaPosting|EmployerReview)\b/i;
const ITEMPROPS = new Set(['comment', 'review', 'reviewbody', 'commenttext', 'suggestedanswer', 'acceptedanswer']);
const TEST_IDS = /^(tweetText|tweet|comment|comment-body|review|review-body|review-text|post-content|reply|markdown-body|issue-title|issue-body)$/i;
const EXCLUDED_TAGS = new Set(['html', 'body', 'main', 'head', 'a', 'button', 'form', 'input', 'textarea', 'select', 'option', 'label', 'script', 'style', 'noscript', 'template']);

const LABELS = [
  [/disqus/, 'Disqus comments'],
  [/comm/, 'Comments'],
  [/review/, 'Reviews'],
  [/repl/, 'Replies'],
  [/discussion/, 'Discussion'],
  [/forum/, 'Forum posts'],
  [/guestbook/, 'Guestbook'],
  [/issue[-_]?title/, 'Issue title'],
  [/issue|markdown/, 'User-written markdown'],
  [/timeline/, 'Comment'],
  [/user|ugc/, 'User content']
];

function labelFor(name) {
  const lower = name.toLowerCase();
  const found = LABELS.find(([pattern]) => pattern.test(lower));
  return found ? found[1] : 'User content';
}

function isUgcName(name) {
  return UGC_NAME.test(name) && !NEGATIVE_PREFIX.test(name) && !NEGATIVE_SUFFIX.test(name);
}

function attributeSelector(name, value) {
  return `[${name}="${String(value).replace(/["\\]/g, '\\$&')}"]`;
}

function textLength(element) {
  let total = 0;
  const stack = [element];
  while (stack.length && total < 20) {
    const node = stack.pop();
    if (node.type === 'text') total += node.data.trim().length;
    if (node.children && !['script', 'style'].includes(node.name)) stack.push(...node.children);
  }
  return total;
}

// Returns { label, reason, suggestedSelector } when the element looks like a
// container of user-generated content, otherwise null.
export function inferUserContent(element) {
  const tag = (element.name || '').toLowerCase();
  if (EXCLUDED_TAGS.has(tag)) return null;
  const attribs = element.attribs || {};
  let result = null;

  if (UGC_TAGS[tag]) {
    result = { label: UGC_TAGS[tag], reason: `<${tag}> element`, suggestedSelector: tag };
  }

  if (!result && attribs.id && isUgcName(attribs.id)) {
    result = {
      label: labelFor(attribs.id),
      reason: `id "${attribs.id}"`,
      suggestedSelector: CSS_IDENT.test(attribs.id) ? `#${attribs.id}` : attributeSelector('id', attribs.id)
    };
  }

  if (!result && attribs.itemtype && SCHEMA_TYPE.test(attribs.itemtype)) {
    const type = attribs.itemtype.match(SCHEMA_TYPE)[1];
    result = { label: type, reason: `schema.org ${type}`, suggestedSelector: `[itemtype*="schema.org/${type}"]` };
  }

  if (!result && attribs.itemprop && ITEMPROPS.has(attribs.itemprop.toLowerCase())) {
    result = { label: labelFor(attribs.itemprop), reason: `itemprop "${attribs.itemprop}"`, suggestedSelector: attributeSelector('itemprop', attribs.itemprop) };
  }

  if (!result) {
    for (const name of ['data-testid', 'data-test', 'data-hook']) {
      if (attribs[name] && TEST_IDS.test(attribs[name])) {
        result = { label: labelFor(attribs[name]), reason: `${name} "${attribs[name]}"`, suggestedSelector: attributeSelector(name, attribs[name]) };
        break;
      }
    }
  }

  if (!result && attribs.class) {
    const match = attribs.class.split(/\s+/).find((name) => name && isUgcName(name));
    if (match) {
      result = {
        label: labelFor(match),
        reason: `class "${match}"`,
        suggestedSelector: CSS_IDENT.test(match) ? `.${match}` : `[class~="${match}"]`
      };
    }
  }

  if (!result) return null;
  return textLength(element) >= 20 ? result : null;
}
