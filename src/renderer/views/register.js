// Function register view.
window.VIEWS.register = {
  title: 'Function register',
  intro: 'Each page is a saved question to Liongard. Point the app at another environment and every page answers it for that client.',
  render(m) {
    return `<div class="tw"><table><thead><tr><th>Page</th><th>Question asked of Liongard</th><th>API data used</th><th>Used for</th></tr></thead><tbody>
      ${m.rows.map(r => `<tr><td><a href="panel.html?id=${r.id}"><b>${esc(r.name)}</b></a></td><td class="wrap">${esc(r.q)}</td><td class="wrap mono" style="font-size:12.5px">${esc(r.calls)}</td><td>${esc(r.use)}</td></tr>`).join('')}
    </tbody></table></div>
    <p class="sub">Every page shows the exact calls under Export → "Show how this page is built", and its rules are in <span class="mono">src/main/panels/&lt;page&gt;.js</span>.</p>`;
  },
  how: () => 'No API calls. This page lists the others.',
};
