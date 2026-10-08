import { useEffect, useState } from 'react'

// Tiny hash router: #/ , #/attacks , #/demo/<id> , #/how , #/anatomy/<id> , #/results
export function parseHash() {
  const [page = '', id = ''] = window.location.hash.replace(/^#\/?/, '').split('/')
  return { page: page || 'home', id: decodeURIComponent(id) }
}

export function useRoute() {
  const [route, setRoute] = useState(parseHash)
  useEffect(() => {
    const onHash = () => {
      setRoute(parseHash())
      window.scrollTo(0, 0)
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])
  return route
}

export const href = {
  home: '#/',
  attacks: '#/attacks',
  demo: (id) => `#/demo/${id}`,
  how: '#/how',
  anatomy: (id) => (id ? `#/anatomy/${id}` : '#/anatomy'),
  results: '#/results',
}
