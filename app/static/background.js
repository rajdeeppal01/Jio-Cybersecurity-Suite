/* ==========================================================================
   JCS OFFLINE AMBIENT CANVAS ANIMATION
   ========================================================================== */
function initAmbientCanvas() {
    const canvas = document.getElementById('ambient-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;
    
    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });
    
    let mouse = { x: width / 2, y: height / 2, tx: width / 2, ty: height / 2 };
    let touch = { x: 0, y: 0, tx: 0, ty: 0, opacity: 0, targetOpacity: 0 };
    
    window.addEventListener('mousemove', (e) => {
        mouse.tx = e.clientX;
        mouse.ty = e.clientY;
    });
    
    window.addEventListener('touchstart', (e) => {
        if (e.touches.length > 0) {
            touch.targetOpacity = 0.22;
            touch.tx = e.touches[0].clientX;
            touch.ty = e.touches[0].clientY;
            
            if (touch.opacity < 0.05) {
                touch.x = touch.tx;
                touch.y = touch.ty;
            }
        }
    }, { passive: true });

    window.addEventListener('touchmove', (e) => {
        if (e.touches.length > 0) {
            touch.tx = e.touches[0].clientX;
            touch.ty = e.touches[0].clientY;
        }
    }, { passive: true });

    const endTouch = () => {
        touch.targetOpacity = 0;
    };
    window.addEventListener('touchend', endTouch, { passive: true });
    window.addEventListener('touchcancel', endTouch, { passive: true });
    
    // Define 3 interactive glowing blobs
    const blobs = [
        { x: Math.random() * width, y: Math.random() * height, r: 350, speed: 0.03, color1: 'rgba(20, 184, 166, 0.08)', color2: 'rgba(20, 184, 166, 0)' },
        { x: Math.random() * width, y: Math.random() * height, r: 450, speed: 0.02, color1: 'rgba(56, 189, 248, 0.06)', color2: 'rgba(56, 189, 248, 0)' },
        { x: Math.random() * width, y: Math.random() * height, r: 400, speed: 0.015, color1: 'rgba(139, 92, 246, 0.05)', color2: 'rgba(139, 92, 246, 0)' }
    ];
    
    // Generate parallax background particles (stars)
    const particles = [];
    for (let i = 0; i < 70; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            r: Math.random() * 1.5 + 0.5,
            depth: Math.random() * 0.4 + 0.1,
            color: `rgba(255, 255, 255, ${Math.random() * 0.25 + 0.1})` // Increased star visibility slightly
        });
    }
    
    function animate() {
        mouse.x += (mouse.tx - mouse.x) * 0.08;
        mouse.y += (mouse.ty - mouse.y) * 0.08;
        
        const scrollY = window.scrollY;
        
        ctx.fillStyle = '#0a0a0c';
        ctx.fillRect(0, 0, width, height);
        
        // Draw parallax stars/particles
        particles.forEach(p => {
            let py = (p.y - scrollY * p.depth) % height;
            if (py < 0) py += height;
            
            ctx.fillStyle = p.color;
            ctx.beginPath();
            ctx.arc(p.x, py, p.r, 0, Math.PI * 2);
            ctx.fill();
        });
        
        // Draw touch glow blob
        touch.opacity += (touch.targetOpacity - touch.opacity) * 0.1;
        if (touch.opacity > 0.01) {
            touch.x += (touch.tx - touch.x) * 0.15;
            touch.y += (touch.ty - touch.y) * 0.15;
            
            const radius = 150;
            const grad = ctx.createRadialGradient(touch.x, touch.y, 0, touch.x, touch.y, radius);
            grad.addColorStop(0, `rgba(20, 184, 166, ${touch.opacity})`);
            grad.addColorStop(0.5, `rgba(20, 184, 166, ${touch.opacity * 0.35})`);
            grad.addColorStop(1, 'rgba(20, 184, 166, 0)');
            
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(touch.x, touch.y, radius, 0, Math.PI * 2);
            ctx.fill();
        }
        
        blobs.forEach((blob, idx) => {
            const targetX = mouse.x + Math.sin(Date.now() * 0.0008 + idx * 2) * 150;
            const targetY = mouse.y + Math.cos(Date.now() * 0.0008 + idx * 2) * 150;
            
            blob.x += (targetX - blob.x) * blob.speed;
            blob.y += (targetY - blob.y) * blob.speed;
            
            const grad = ctx.createRadialGradient(blob.x, blob.y, 0, blob.x, blob.y, blob.r);
            grad.addColorStop(0, blob.color1);
            grad.addColorStop(1, blob.color2);
            
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(blob.x, blob.y, blob.r, 0, Math.PI * 2);
            ctx.fill();
        });
        
        requestAnimationFrame(animate);
    }
    
    animate();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAmbientCanvas);
} else {
    initAmbientCanvas();
}
