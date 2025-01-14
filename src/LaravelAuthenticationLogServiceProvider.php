<?php

namespace Rappasoft\LaravelAuthenticationLog;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Events\Dispatcher;
use Rappasoft\LaravelAuthenticationLog\Commands\PurgeAuthenticationLogCommand;
use Rappasoft\LaravelAuthenticationLog\Listeners\FailedLoginListener;
use Rappasoft\LaravelAuthenticationLog\Listeners\LoginListener;
use Rappasoft\LaravelAuthenticationLog\Listeners\LogoutListener;
use Rappasoft\LaravelAuthenticationLog\Listeners\OtherDeviceLogoutListener;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class LaravelAuthenticationLogServiceProvider extends PackageServiceProvider
{
    /**
     * @throws BindingResolutionException
     */
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-authentication-log')
            ->hasConfigFile()
            ->hasTranslations()
            ->hasViews()
            ->hasMigrations([
                'create_authentication_log_table',
                'add_browser_and_browser_os_to_log_table',
                'update_user_agent_column',
            ])
            ->hasCommand(PurgeAuthenticationLogCommand::class);

        if (! $this->app->runningInConsole()) {
            $events = $this->app->make(Dispatcher::class);

            $events->listen(config('authentication-log.events.login', Login::class), LoginListener::class);
            $events->listen(config('authentication-log.events.failed', Failed::class), FailedLoginListener::class);
            $events->listen(config('authentication-log.events.logout', Logout::class), LogoutListener::class);
            $events->listen(config('authentication-log.events.other-device-logout', OtherDeviceLogout::class), OtherDeviceLogoutListener::class);
        }
    }
}
