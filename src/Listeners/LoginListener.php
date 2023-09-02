<?php

namespace Rappasoft\LaravelAuthenticationLog\Listeners;

use Illuminate\Auth\Events\Login;
use Illuminate\Support\Carbon;
use Rappasoft\LaravelAuthenticationLog\Models\AuthenticationLog;
use Rappasoft\LaravelAuthenticationLog\Notifications\NewDevice;
use WhichBrowser\Parser;

class LoginListener extends EventListener
{
    public function handle($event): void
    {
        if (! $this->isListenerForEvent($event, 'login', Login::class)) {
            return;
        }

        if (! $this->isLoggable($event)) {
            return;
        }

        $user = $event->user;

        $log = $user->authentications()->create([
            'ip_address' => $this->request->ip(),
            'user_agent' => $this->request->userAgent(),
            'login_at' => now(),
            'login_successful' => true,
            'location' => config('authentication-log.notifications.new-device.location') ? optional(geoip()->getLocation($this->request->ip()))->toArray() : null,
        ]);

        if ($this->shouldNotify($user, $log)) {
            $newDevice = config('authentication-log.notifications.new-device.template') ?? NewDevice::class;
            $user->notify(new $newDevice($log));
        }
    }

    protected function shouldNotify($user, AuthenticationLog $log): bool
    {
        if (! config('authentication-log.notifications.new-device.enabled')) {
            return false;
        }

        if ($this->userWasRecentlyCreated($user)) {
            return false;
        }

        if ($this->isFirstLogin($user, $log)) {
            return false;
        }

        if ($this->hasKnownDevices($user, $log)) {
            return false;
        }

        return true;
    }

    protected function userWasRecentlyCreated($user): bool
    {
        return Carbon::parse($user->{$user->getCreatedAtColumn()})->diffInMinutes(Carbon::now()) < 1;
    }

    protected function isFirstLogin($user, AuthenticationLog $log): bool
    {
        return $user->authentications()->where('id', '!=', $log->id)->where('login_successful', true)->doesntExist();
    }

    protected function hasKnownDevices($user, AuthenticationLog $log): bool
    {
        $parser = new Parser($this->request->userAgent());

        return $user->authentications()
            ->where('id', '!=', $log->id)
            ->where('ip_address', $this->request->ip())
            ->where('browser', $parser->browser->name)
            ->where('browser_os', $parser->os->name)
            ->where('login_successful', true)
            ->exists();
    }
}
